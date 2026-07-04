// scanner/mod.rs
//
// Public interface for the scanner subsystem.
//
// Architecture note (rust-daemon-skill):
//   The scanner subsystem is intentionally split into two concerns:
//     1. `yara_engine` — pure signature matching, CPU-bound, fuzz-testable in isolation
//     2. `compute_sha256` — re-exported from the parent crate's existing scanner.rs
//        so callers access all scanning primitives through one module path.
//
// Any future addition (ClamAV FFI wrapper, ML-based heuristic, etc.) gets its
// own sub-module here and is wrapped behind a safe Rust API before being
// exposed publicly.

pub mod yara_engine;

// Re-export the SHA-256 helper already implemented in the parent scanner module
// so quarantine_safe.rs can call `crate::scanner::compute_sha256` cleanly.
pub use super::scanner::compute_sha256;
