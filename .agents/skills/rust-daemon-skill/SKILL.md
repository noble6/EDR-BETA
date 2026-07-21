\---

name: rust-daemon-skill

description: Use when writing or modifying the av-daemon Rust binary — covers async architecture, error handling, and safe scanning patterns for the antivirus daemon.

\---



\# Rust Antivirus Daemon Conventions



\## Purpose

Guide development of av-daemon: a Rust background service that watches filesystem paths, matches files against YARA/ClamAV signatures, and quarantines threats.



\## Core Conventions

\- Use Tokio as the async runtime for all I/O — never block the main event loop with synchronous file reads on large files.

\- Use `thiserror` for daemon-internal error types and `anyhow` only at the binary's top level (main.rs), not in library code.

\- All filesystem watching goes through `notify` crate (inotify/fanotify backend) wrapped in an async channel.

\- Signature matching logic must be isolated in its own module (`scanner::yara\_engine`) so it can be swapped or fuzz-tested independently.

\- Any FFI boundary (e.g., linking libclamav) must be wrapped in a safe Rust API — no raw pointers exposed outside the FFI module.



\## Common Pitfalls

\- Do not spawn unbounded tasks per scanned file; use a bounded worker pool (semaphore-limited) to avoid resource exhaustion during large scans.

\- Do not hold quarantine file locks across await points — this can deadlock under concurrent scan triggers.

\- Avoid `unwrap()`/`expect()` in any code path that runs on untrusted file content; always propagate `Result`.



\## Suggested Module Structure (scaffolding only, no code)

\- src/main.rs — daemon entrypoint, config load, signal handling

\- src/watcher.rs — filesystem event stream

\- src/scanner/ — signature matching engine

\- src/quarantine.rs — isolation logic

\- src/ipc.rs — communication with av-cli

\- src/config.rs — daemon.conf parsing

