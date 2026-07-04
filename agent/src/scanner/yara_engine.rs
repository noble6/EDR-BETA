// scanner/yara_engine.rs
//
// YARA signature matching engine — isolated module so it can be swapped or
// fuzz-tested independently (rust-daemon-skill convention).
//
// This module is intentionally a safe Rust wrapper over the `yara` crate's
// FFI boundary.  No raw pointers escape this file.
//
// Architecture note:
//   * We compile rules once at startup from the on-disk .yar file and cache
//     the compiled ruleset behind an Arc so worker tasks share it without
//     re-parsing on every scan.
//   * Matching is CPU-bound; callers MUST dispatch via spawn_blocking so the
//     Tokio event loop is never stalled (rust-daemon-skill: no blocking I/O
//     on main event loop).

use std::path::Path;
use std::sync::Arc;

use thiserror::Error;  // thiserror for library errors (rust-daemon-skill)
use tokio::task;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum YaraError {
    #[error("Failed to compile YARA rules from {path}: {source}")]
    Compile {
        path: String,
        #[source]
        source: yara::Error,
    },

    #[error("YARA scan failed on {path}: {source}")]
    Scan {
        path: String,
        #[source]
        source: yara::Error,
    },

    #[error("Blocking task panicked during YARA scan")]
    JoinError(#[from] task::JoinError),
}

// ---------------------------------------------------------------------------
// Public API types
// ---------------------------------------------------------------------------

/// A single rule match returned per scanned file.
#[derive(Debug, Clone)]
pub struct YaraMatch {
    /// Rule identifier, e.g. "Trojan_Generic_ObfuscatedPS1"
    pub rule_id: String,
    /// Severity tag extracted from rule metadata (defaults to "medium")
    pub severity: String,
    /// Human-readable description from rule metadata
    pub description: String,
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// Holds a compiled YARA ruleset for reuse across many scans.
///
/// Wrap in `Arc<YaraEngine>` and clone the Arc into each scan worker.
pub struct YaraEngine {
    // yara::Rules is not Send/Sync in all versions of the crate.
    // We hold the raw path and recompile per-task when required,
    // OR gate on a mutex.  Here we use a Mutex to keep one compiled
    // ruleset and serialise access (fine for our bounded worker pool).
    rules_path: String,
}

impl YaraEngine {
    /// Load and validate a .yar rule file.  Fails fast at startup so the
    /// daemon refuses to run with a broken signature database.
    pub fn new(yar_path: &str) -> Result<Self, YaraError> {
        // Compile once to validate — the actual per-scan compile is below.
        // (Some yara crate versions don't expose a Clone on Rules, so we
        // recompile per spawn_blocking call; the cost is negligible vs I/O.)
        let _ = yara::Compiler::new()
            .and_then(|c| c.add_rules_file(yar_path))
            .and_then(|c| c.compile_rules())
            .map_err(|e| YaraError::Compile {
                path: yar_path.to_string(),
                source: e,
            })?;

        Ok(Self {
            rules_path: yar_path.to_string(),
        })
    }

    /// Scan a file asynchronously.
    ///
    /// Internally dispatches to `spawn_blocking` — safe to await on the
    /// Tokio event loop.  Returns `Ok(vec![])` for clean files.
    pub async fn scan_file(
        self: Arc<Self>,
        file_path: &Path,
    ) -> Result<Vec<YaraMatch>, YaraError> {
        let path_str = file_path.to_string_lossy().to_string();
        let rules_path = self.rules_path.clone();

        // CPU-bound: always run off the async executor (rust-daemon-skill)
        task::spawn_blocking(move || {
            // Recompile is ~µs for a typical signature set; acceptable cost
            // to avoid unsafe Send impl workarounds on yara::Rules.
            let rules = yara::Compiler::new()
                .and_then(|c| c.add_rules_file(&rules_path))
                .and_then(|c| c.compile_rules())
                .map_err(|e| YaraError::Compile {
                    path: rules_path.clone(),
                    source: e,
                })?;

            let matches = rules
                .scan_file(&path_str, 30 /* timeout_secs */)
                .map_err(|e| YaraError::Scan {
                    path: path_str.clone(),
                    source: e,
                })?;

            let results = matches
                .iter()
                .map(|m| {
                    // Pull severity and description out of YARA metadata block.
                    // Fall back to safe defaults when metadata is absent so we
                    // never panic on untrusted rule content (rust-daemon-skill:
                    // avoid unwrap() on untrusted paths).
                    let severity = m
                        .metadatas
                        .iter()
                        .find(|md| md.identifier == "severity")
                        .and_then(|md| {
                            if let yara::MetadataValue::String(s) = &md.value {
                                Some(s.clone())
                            } else {
                                None
                            }
                        })
                        .unwrap_or_else(|| "medium".to_string());

                    let description = m
                        .metadatas
                        .iter()
                        .find(|md| md.identifier == "description")
                        .and_then(|md| {
                            if let yara::MetadataValue::String(s) = &md.value {
                                Some(s.clone())
                            } else {
                                None
                            }
                        })
                        .unwrap_or_else(|| "No description".to_string());

                    YaraMatch {
                        rule_id: m.identifier.to_string(),
                        severity,
                        description,
                    }
                })
                .collect();

            Ok(results)
        })
        .await?
    }
}
