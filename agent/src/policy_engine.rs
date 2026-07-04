// policy_engine.rs
//
// Policy enforcement — decides what to do with a classified file.
//
// STEP 2: enforce_quarantine() now delegates to quarantine_safe::quarantine_file()
// which provides:
//   - Atomic move-then-verify (EXDEV cross-device fallback)
//   - Execute-bit stripping (0o600)
//   - JSON metadata sidecar (.meta.json) per quarantined file
//   - Structured audit log emission for backend dashboard
//
// The old inline fs::rename() + ad-hoc chmod logic is removed.
// Process-kill on the original path is preserved here as a best-effort
// measure (it is path-based and cannot guarantee catching all execution
// flows without eBPF PID attribution).

use std::path::Path;
use std::process::Command;
use log::{info, error, warn};

use crate::quarantine_safe;
use crate::scanner::compute_sha256;

/// Enforce policy action for a classified file.
///
/// Called from main.rs apply_policy() with the YARA-match context so the
/// quarantine sidecar can record the matched signature ID and severity.
///
/// # Arguments
/// * `file_path`     — Absolute path of the detected file
/// * `quarantine_dir`— Quarantine root from daemon config
/// * `sha256`        — Pre-computed hash (avoids re-reading the file)
/// * `signature_id`  — Matched YARA rule identifier (e.g. "Ransomware_ShadowCopy_Deletion")
/// * `severity`      — Severity tag from matched rule ("low"|"medium"|"high"|"critical")
pub fn enforce_quarantine(
    file_path: &Path,
    quarantine_dir: &str,
    sha256: &str,
    signature_id: &str,
    severity: &str,
) {
    if !file_path.exists() {
        warn!("enforce_quarantine: file no longer exists: {:?}", file_path);
        return;
    }

    info!(
        "policy_engine: quarantine_start path={:?} signature={} severity={}",
        file_path, signature_id, severity
    );

    // Delegate to quarantine_safe for atomic move + metadata sidecar
    match quarantine_safe::quarantine_file(
        file_path,
        quarantine_dir,
        sha256,
        signature_id,
        severity,
    ) {
        Ok(dest) => {
            info!(
                "policy_engine: quarantine_success path={:?} dest={:?}",
                file_path, dest
            );
        }
        Err(e) => {
            error!(
                "policy_engine: quarantine_failed path={:?} error={}",
                file_path, e
            );
            // If quarantine failed, the file is still at its original path.
            // Do NOT silently drop — the detection must surface in logs so
            // the operator can investigate.
        }
    }

    // Best-effort: kill any process running the file from its original path.
    // This is path-based only; for accurate PID attribution use eBPF events.
    // Note: this runs regardless of quarantine success/failure to maximise
    // the chance of stopping an active threat.
    if let Some(path_str) = file_path.to_str() {
        let status = Command::new("pkill").arg("-f").arg(path_str).status();
        match status {
            Ok(s) if s.success() => {
                info!("policy_engine: pkill_succeeded path={}", path_str);
            }
            Ok(_) => {
                // Exit code 1 from pkill means no matching process found — not an error
            }
            Err(e) => {
                warn!("policy_engine: pkill_error path={} error={}", path_str, e);
            }
        }
    }
}

/// Legacy shim — forwards to enforce_quarantine() with unknown signature context.
///
/// Kept for call-sites that haven't been updated to pass YARA match metadata.
/// Will be removed once all callers provide full context.
#[deprecated(
    since = "0.2.0",
    note = "Use enforce_quarantine() with signature_id and severity arguments"
)]
pub fn enforce_quarantine_legacy(file_path: &Path, quarantine_dir: &str) {
    // Re-compute hash for sidecar — this is an extra read but the legacy
    // path is expected to be phased out quickly.
    let sha256 = compute_sha256(file_path)
        .unwrap_or_else(|_| "unknown".to_string());

    enforce_quarantine(
        file_path,
        quarantine_dir,
        &sha256,
        "unknown_legacy",
        "medium",
    );
}
