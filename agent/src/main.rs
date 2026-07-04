// main.rs — av-daemon entrypoint
//
// STEP 3: YARA scanning wired into the event loop.
//
// Detection pipeline per file event:
//   1. Compute SHA-256 hash
//   2. [NEW] Run YARA signature scan (spawn_blocking — never blocks Tokio loop)
//      → On hit: quarantine immediately via policy_engine; skip backend lookup
//      → On miss: continue to backend reputation lookup
//   3. Check local LRU cache for known hash
//   4. Backend hash lookup → verdict-based policy
//   5. Upload unknown file for sandbox analysis → poll verdict
//   6. Offline queue on backend failure
//
// Architecture decisions:
//   - YARA is checked first so known-malicious files are stopped even without
//     network connectivity (offline detection capability).
//   - The YARA engine is Arc-wrapped so it can be cloned cheaply into each
//     worker iteration without re-compiling rules.
//   - No blocking I/O on the Tokio event loop (rust-daemon-skill).

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use log::{debug, error, info, warn};
use tokio::sync::mpsc;

mod api_client;
mod config;
mod ebpf_monitor;
mod monitor;
mod offline_queue;
mod policy_engine;
mod quarantine_safe;  // Step 2: atomic quarantine module
mod scanner;          // scanner::yara_engine + compute_sha256

use scanner::yara_engine::YaraEngine;

// ---------------------------------------------------------------------------
// Logger init
// ---------------------------------------------------------------------------
fn init_logger() {
    std::env::set_var("RUST_LOG", "info");
    env_logger::init();
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
#[tokio::main]
async fn main() {
    init_logger();
    info!("Starting Hybrid EDR Endpoint Agent");

    // Load config from config.json (no hardcoded secrets)
    let cfg = config::load_config("config.json");
    let quarantine_target = cfg.quarantine_dir.clone();

    // --- STEP 3: Initialise YARA engine at startup ---
    // Rules compiled once and shared via Arc across all scan iterations.
    // Daemon refuses to start if the signature file is missing or malformed —
    // this fails fast rather than silently skipping signature matching.
    let yara_engine: Arc<YaraEngine> = {
        let yar_path = cfg.signatures_path.as_deref().unwrap_or("/opt/antivirus/signatures/signatures.yar");
        match YaraEngine::new(yar_path) {
            Ok(engine) => {
                info!("yara_engine_loaded signatures_path={}", yar_path);
                Arc::new(engine)
            }
            Err(e) => {
                error!("yara_engine_load_failed error={} — daemon cannot start without signatures", e);
                std::process::exit(1);
            }
        }
    };

    // Channel: inotify → async worker loop
    let (tx, mut rx) = mpsc::channel(100);

    // Mount eBPF kernel sensor (optional — falls back to inotify)
    let _ebpf = match ebpf_monitor::EbpfMonitor::new() {
        Ok(m) => {
            info!("Kernel eBPF Sensor successfully loaded inside EDR agent.");
            Some(m)
        }
        Err(e) => {
            warn!("Kernel sensors disabled: {}. Falling back to standard inotify...", e);
            None
        }
    };

    // Local LRU cache for known hashes (avoids repeated backend round-trips)
    let mut cache = scanner::LocalCache::new(cfg.cache_capacity);
    let mut processing_queue: HashSet<String> = HashSet::new();

    // HTTP API client for backend communication
    let api = api_client::AgentApiClient::new(cfg.clone());

    // Spawn inotify watcher thread (notify crate is synchronous — runs off Tokio)
    let _watcher = match monitor::start_monitoring(&cfg.monitor_dir, tx) {
        Ok(w) => w,
        Err(e) => {
            error!("Failed to start native file monitor: {}", e);
            std::process::exit(1);
        }
    };

    info!(
        "Agent running, listening for file creation on {}...",
        cfg.monitor_dir
    );

    // -----------------------------------------------------------------------
    // Async event loop
    // -----------------------------------------------------------------------
    while let Some(path) = rx.recv().await {
        // Attempt to drain offline queue before processing the new event
        if let Err(e) =
            flush_offline_queue(&api, &cfg.offline_queue_path, &mut cache, &quarantine_target).await
        {
            debug!("Offline queue flush skipped: {}", e);
        }

        let path_str = path.to_string_lossy().to_string();

        // Deduplicate: skip files already in-flight
        if processing_queue.contains(&path_str) {
            continue;
        }
        processing_queue.insert(path_str.clone());

        // ── 1. Hash the file ──────────────────────────────────────────────
        let sha256 = match scanner::compute_sha256(&path) {
            Ok(h) => h,
            Err(e) => {
                debug!("Could not read/hash file (likely swept up early): {:?}", e);
                processing_queue.remove(&path_str);
                continue;
            }
        };

        info!("New file detected: {:?} | SHA256: {}", path, sha256);

        // ── 2. YARA local signature scan (STEP 3) ─────────────────────────
        // Run before backend lookup: catches known threats offline and stops
        // them immediately without network round-trips.
        //
        // Clone the Arc — zero cost, shares the compiled ruleset.
        let engine_ref = Arc::clone(&yara_engine);
        match engine_ref.scan_file(&path).await {
            Ok(matches) if !matches.is_empty() => {
                // Use the highest-severity match as the canonical detection
                let hit = &matches[0];
                info!(
                    "yara_hit path={:?} rule={} severity={}",
                    path, hit.rule_id, hit.severity
                );

                // Quarantine immediately — no backend round-trip needed
                policy_engine::enforce_quarantine(
                    &path,
                    &quarantine_target,
                    &sha256,
                    &hit.rule_id,
                    &hit.severity,
                );

                // Cache the local verdict so offline queue flushes recognise
                // this hash without re-scanning
                cache.insert(
                    sha256.clone(),
                    scanner::Verdict {
                        classification: "malicious".to_string(),
                        risk_score: 100.0,
                    },
                );

                processing_queue.remove(&path_str);
                continue; // Skip backend lookup — already handled
            }
            Ok(_) => {
                // Clean YARA result — proceed to backend reputation lookup
                debug!("yara_clean path={:?} sha256={}", path, sha256);
            }
            Err(e) => {
                // YARA scan error is non-fatal: log and continue to backend
                // lookup so the file is still assessed.
                warn!("yara_scan_error path={:?} error={} — falling back to backend", path, e);
            }
        }

        // ── 3. Local LRU cache check ──────────────────────────────────────
        if let Some(verdict) = cache.get(&sha256) {
            info!(
                "local_cache_hit sha256={} classification={} risk_score={}",
                sha256, verdict.classification, verdict.risk_score
            );
            apply_policy(&path, &quarantine_target, &sha256, &verdict.classification);
            processing_queue.remove(&path_str);
            continue;
        }

        // ── 4 & 5. Backend hash lookup → upload → poll verdict ─────────────
        match api.lookup_hash(&sha256).await {
            Ok(Some(verdict)) => {
                info!(
                    "backend_hash_hit sha256={} classification={} risk_score={}",
                    sha256, verdict.classification, verdict.risk_score
                );
                cache.insert(sha256.clone(), verdict.clone());
                apply_policy(&path, &quarantine_target, &sha256, &verdict.classification);
            }
            Ok(None) => {
                info!("backend_hash_miss sha256={}", sha256);
                match api.upload_file(&path).await {
                    Ok(task_id) => {
                        info!("file_uploaded task_id={} sha256={}", task_id, sha256);
                        if let Some(verdict) = api.poll_task_status(&task_id).await {
                            info!(
                                "verdict_received task_id={} classification={} risk_score={}",
                                task_id, verdict.classification, verdict.risk_score
                            );
                            cache.insert(sha256.clone(), verdict.clone());
                            apply_policy(&path, &quarantine_target, &sha256, &verdict.classification);
                        } else {
                            error!(
                                "verdict_timeout_or_failed task_id={} sha256={}",
                                task_id, sha256
                            );
                            enqueue_offline(&cfg.offline_queue_path, &path_str, &sha256);
                        }
                    }
                    Err(api_error) => {
                        error!("api_upload_failed sha256={} error={}", sha256, api_error);
                        enqueue_offline(&cfg.offline_queue_path, &path_str, &sha256);
                    }
                }
            }
            Err(e) => {
                error!("api_lookup_failed sha256={} error={}", sha256, e);
                enqueue_offline(&cfg.offline_queue_path, &path_str, &sha256);
            }
        }

        processing_queue.remove(&path_str);
    }
}

// ---------------------------------------------------------------------------
// Policy dispatch
// ---------------------------------------------------------------------------

/// Route a classified file to the appropriate action.
///
/// For malicious files, sha256 is passed through so quarantine_safe can
/// write it into the metadata sidecar without re-reading the file.
fn apply_policy(path: &Path, quarantine_dir: &str, sha256: &str, classification: &str) {
    match classification {
        "malicious" => {
            info!(
                "policy_action action=quarantine classification=malicious path={:?}",
                path
            );
            // Use "backend_verdict" as signature_id to distinguish backend-driven
            // quarantines from local YARA hits in the audit log.
            policy_engine::enforce_quarantine(
                path,
                quarantine_dir,
                sha256,
                "backend_verdict",
                "high",
            );
        }
        "suspicious" => {
            info!(
                "policy_action action=alert classification=suspicious path={:?}",
                path
            );
            // Alert only — no quarantine for suspicious until confirmed malicious.
            // Future: send alert event to backend /av/scans endpoint.
        }
        _ => {
            info!(
                "policy_action action=allow classification=benign path={:?}",
                path
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Offline queue helper
// ---------------------------------------------------------------------------

fn enqueue_offline(queue_path: &str, path_str: &str, sha256: &str) {
    let _ = offline_queue::enqueue(
        queue_path,
        &offline_queue::QueuedEvent {
            path: path_str.to_string(),
            sha256: sha256.to_string(),
        },
    );
}

// ---------------------------------------------------------------------------
// Offline queue flush
// ---------------------------------------------------------------------------

async fn flush_offline_queue(
    api: &api_client::AgentApiClient,
    queue_path: &str,
    cache: &mut scanner::LocalCache,
    quarantine_dir: &str,
) -> Result<(), String> {
    let events = offline_queue::load_all(queue_path);
    if events.is_empty() {
        return Ok(());
    }

    let mut remaining = Vec::new();
    for event in events {
        let event_path = Path::new(&event.path);
        if !event_path.exists() {
            continue;
        }

        match api.lookup_hash(&event.sha256).await {
            Ok(Some(verdict)) => {
                cache.insert(event.sha256.clone(), verdict.clone());
                apply_policy(event_path, quarantine_dir, &event.sha256, &verdict.classification);
            }
            Ok(None) => {
                remaining.push(event);
            }
            Err(_) => {
                remaining.push(event);
            }
        }
    }

    offline_queue::rewrite(queue_path, &remaining)
}
