\---

name: quarantine-handling-skill

description: Use when implementing or reviewing quarantine logic — ensures isolated malware is never executable and metadata is preserved for audit.

\---



\# Quarantine Handling Rules



\## Purpose

Ensure detected malware is safely isolated without risk of accidental execution or data loss.



\## Core Rules

\- Never write quarantined files with executable permissions; strip execute bits immediately on isolation.

\- Store quarantined files encrypted-at-rest (e.g., AES-256) so accidental access via file explorer or backup tools doesn't trigger execution.

\- Preserve a metadata sidecar per quarantined item: original path, SHA-256 hash, matched signature ID, detection timestamp, and daemon version.

\- Quarantine actions must be atomic — move-then-verify, never delete-then-copy, to avoid data loss on crash mid-operation.



\## Restore/Delete Workflow

\- Restoring a file requires explicit admin action through av-cli or the backend dashboard, never automatic.

\- Deleting a quarantined file should require confirmation and log the action with the acting user's identity.



\## Audit Requirements

\- Every quarantine event must emit a structured log entry consumed by the backend for dashboard visibility.

