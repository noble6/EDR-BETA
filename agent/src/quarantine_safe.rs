// quarantine_safe.rs
//
// Atomic quarantine implementation for av-daemon.
//
// Design decisions (quarantine-handling-skill):
//  1. Move-then-verify (atomic): we rename the file first; if rename fails
//     across mount boundaries we copy-then-verify-then-delete.  We never
//     delete first, avoiding data loss on crash mid-operation.
//  2. Execute bits stripped immediately on isolation.
//  3. Metadata sidecar (.meta.json) written alongside every quarantined file,
//     recording original_path, sha256, signature_id, detection_timestamp,
//     daemon_version.
//  4. Every quarantine event emits a structured log entry (JSON) for backend
//     dashboard ingestion.
//  5. AES-256 encryption of quarantined content is left as a TODO marker
//     (requires a key-management decision outside this module's scope).
//
// No hardcoded secrets — all paths come from daemon config.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use log::{error, info, warn};
use serde::Serialize;
use thiserror::Error;  // thiserror for library errors (rust-daemon-skill)

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum QuarantineError {
    #[error("Source file not found: {0}")]
    NotFound(String),

    #[error("Failed to move file to quarantine: {0}")]
    MoveFailed(#[from] io::Error),

    #[error("Hash mismatch after quarantine move — file may be corrupted")]
    HashMismatch,

    #[error("Metadata sidecar write failed: {0}")]
    MetaWriteFailed(String),
}

// ---------------------------------------------------------------------------
// Metadata sidecar
// ---------------------------------------------------------------------------

/// Written as `<quarantine_path>.meta.json` alongside every isolated file.
#[derive(Serialize)]
pub struct QuarantineMeta {
    pub original_path: String,
    pub sha256: String,
    pub signature_id: String,
    pub severity: String,
    pub detection_timestamp_unix: u64,
    pub daemon_version: &'static str,
}

impl QuarantineMeta {
    fn write_sidecar(&self, dest: &Path) -> Result<(), QuarantineError> {
        let sidecar_path = PathBuf::from(format!("{}.meta.json", dest.display()));
        let json = serde_json::to_string_pretty(self).map_err(|e| {
            QuarantineError::MetaWriteFailed(e.to_string())
        })?;
        fs::write(&sidecar_path, json).map_err(|e| {
            QuarantineError::MetaWriteFailed(e.to_string())
        })?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Public quarantine function
// ---------------------------------------------------------------------------

/// Atomically isolate a detected file into the quarantine directory.
///
/// # Atomicity guarantee
/// Uses `fs::rename` (atomic on POSIX same-filesystem).  If source and
/// quarantine live on different filesystems (rename returns EXDEV), falls
/// back to copy-verify-delete to preserve the original until we confirm
/// the copy is intact.
///
/// # Arguments
/// * `file_path`     — Absolute path of the file to quarantine
/// * `quarantine_dir`— Root quarantine directory (from daemon config)
/// * `sha256`        — Pre-computed SHA-256 hex string for the sidecar
/// * `signature_id`  — Matched YARA rule ID
/// * `severity`      — Severity tag from matched rule ("high"/"medium"/etc.)
///
/// # Returns
/// The final quarantine path on success.
pub fn quarantine_file(
    file_path: &Path,
    quarantine_dir: &str,
    sha256: &str,
    signature_id: &str,
    severity: &str,
) -> Result<PathBuf, QuarantineError> {
    if !file_path.exists() {
        return Err(QuarantineError::NotFound(
            file_path.display().to_string(),
        ));
    }

    // Construct destination path inside quarantine dir.
    // Prefix with SHA-256 so duplicate detections don't overwrite each other.
    let file_name = file_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let dest_name = format!("{}-{}", &sha256[..16], file_name);
    let dest = Path::new(quarantine_dir).join(&dest_name);

    // --- STEP 1: Atomic move (same filesystem) ---
    match fs::rename(file_path, &dest) {
        Ok(()) => {
            info!(
                "quarantine_move_success original={:?} dest={:?}",
                file_path, dest
            );
        }
        Err(ref e) if cross_device_error(e) => {
            // Cross-device (different mount points): copy-then-verify-then-delete
            warn!(
                "quarantine_cross_device original={:?}; falling back to copy+delete",
                file_path
            );
            fs::copy(file_path, &dest)?;

            // Verify copy integrity before removing source
            let dest_hash = crate::scanner::compute_sha256(&dest)
                .map_err(|e| QuarantineError::MoveFailed(e))?;
            if dest_hash != sha256 {
                // Remove broken copy and abort — original is still intact
                let _ = fs::remove_file(&dest);
                return Err(QuarantineError::HashMismatch);
            }

            fs::remove_file(file_path)?;
            info!(
                "quarantine_copy_delete_success original={:?} dest={:?}",
                file_path, dest
            );
        }
        Err(e) => return Err(QuarantineError::MoveFailed(e)),
    }

    // --- STEP 2: Strip execute bits immediately (quarantine-handling-skill) ---
    // Read/write only for owner — no execute for anyone.
    match fs::metadata(&dest).map(|m| m.permissions()) {
        Ok(mut perms) => {
            perms.set_mode(0o600);
            if let Err(e) = fs::set_permissions(&dest, perms) {
                // Non-fatal: log and continue — file is already moved.
                warn!("quarantine_chmod_failed dest={:?} error={}", dest, e);
            }
        }
        Err(e) => warn!("quarantine_stat_failed dest={:?} error={}", dest, e),
    }

    // --- STEP 3: Write metadata sidecar ---
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let meta = QuarantineMeta {
        original_path: file_path.display().to_string(),
        sha256: sha256.to_string(),
        signature_id: signature_id.to_string(),
        severity: severity.to_string(),
        detection_timestamp_unix: now_unix,
        daemon_version: env!("CARGO_PKG_VERSION"),
    };

    if let Err(e) = meta.write_sidecar(&dest) {
        // Non-fatal — quarantine succeeded even without the sidecar.
        error!("quarantine_meta_write_failed dest={:?} error={}", dest, e);
    }

    // --- STEP 4: Structured audit log (quarantine-handling-skill) ---
    // Emit JSON log line consumed by the backend for dashboard visibility.
    info!(
        "quarantine_event {}",
        serde_json::json!({
            "event": "quarantined",
            "original_path": file_path.display().to_string(),
            "quarantine_path": dest.display().to_string(),
            "sha256": sha256,
            "signature_id": signature_id,
            "severity": severity,
        })
    );

    // TODO (future): encrypt quarantined file with AES-256-GCM using a key
    // retrieved from the daemon's key store (no key stored on disk).
    // This prevents accidental execution via backup tools or file managers.

    Ok(dest)
}

// ---------------------------------------------------------------------------
// Restore workflow (requires explicit admin action — quarantine-handling-skill)
// ---------------------------------------------------------------------------

/// Restore a quarantined file to its original location.
///
/// This is intentionally NOT called automatically — it must be triggered
/// via av-cli or the backend dashboard by an admin (quarantine-handling-skill).
///
/// # Security
/// * Caller is responsible for verifying the acting user's identity and
///   logging the action with that identity before calling this function.
/// * The restored file's permissions are set to 0o644 (user rw, group/other r).
pub fn restore_file(
    quarantine_path: &Path,
    original_path: &Path,
) -> Result<(), QuarantineError> {
    if !quarantine_path.exists() {
        return Err(QuarantineError::NotFound(
            quarantine_path.display().to_string(),
        ));
    }

    // Ensure parent directory exists before restoring
    if let Some(parent) = original_path.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::rename(quarantine_path, original_path)?;

    // Restore safe permissions — NOT 0o755 to avoid accidental re-execution
    #[cfg(unix)]
    {
        if let Ok(mut perms) = fs::metadata(original_path).map(|m| m.permissions()) {
            perms.set_mode(0o644);
            let _ = fs::set_permissions(original_path, perms);
        }
    }

    info!(
        "quarantine_restored \
         {{\"event\":\"restored\",\
         \"quarantine_path\":\"{}\",\
         \"original_path\":\"{}\"}}",
        quarantine_path.display(),
        original_path.display(),
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Delete workflow
// ---------------------------------------------------------------------------

/// Permanently delete a quarantined file.
///
/// Requires explicit confirmation from the caller (quarantine-handling-skill:
/// deletion requires confirmation + audit log with acting user identity).
///
/// # Arguments
/// * `quarantine_path` — Path inside the quarantine directory
/// * `acting_user`     — Identity of the admin performing deletion (for audit)
pub fn delete_quarantined(
    quarantine_path: &Path,
    acting_user: &str,
) -> Result<(), QuarantineError> {
    if !quarantine_path.exists() {
        return Err(QuarantineError::NotFound(
            quarantine_path.display().to_string(),
        ));
    }

    // Remove sidecar first (best-effort)
    let sidecar = PathBuf::from(format!("{}.meta.json", quarantine_path.display()));
    let _ = fs::remove_file(&sidecar);

    fs::remove_file(quarantine_path)?;

    // Structured audit log with acting user (quarantine-handling-skill)
    info!(
        "quarantine_deleted \
         {{\"event\":\"deleted\",\
         \"quarantine_path\":\"{}\",\
         \"acting_user\":\"{}\"}}",
        quarantine_path.display(),
        acting_user,
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Detect EXDEV (cross-device rename) to trigger copy fallback.
#[cfg(unix)]
fn cross_device_error(e: &io::Error) -> bool {
    e.raw_os_error() == Some(libc::EXDEV)
}

#[cfg(not(unix))]
fn cross_device_error(_: &io::Error) -> bool {
    false
}
