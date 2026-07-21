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
pub mod hash_engine;
pub mod verdict;
pub mod file_guard;

pub use hash_engine::compute_sha256;
pub use hash_engine::LocalCache;
pub use verdict::Verdict;
