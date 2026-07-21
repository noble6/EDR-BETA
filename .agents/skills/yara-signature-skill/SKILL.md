\---

name: yara-signature-skill

description: Use when authoring or validating YARA rules for the antivirus signature database — ensures compatibility with ClamAV's YARA constraints.

\---



\# YARA Signature Authoring Rules



\## Purpose

Ensure every rule added to signatures.db is valid, efficient, and compatible with ClamAV's restricted YARA implementation.



\## Hard Constraints (ClamAV YARA support)

\- Maximum 64 strings per rule — split detection logic across multiple rules if exceeded \[web:1].

\- No YARA modules (pe, elf, cuckoo, etc.) are supported — conditions must rely only on string/byte matching \[web:1].

\- No precompiled `yarac` rule files — only plaintext `.yar`/`.yara` source is accepted \[web:1].

\- No global rules — every rule must be independently evaluable.



\## Rule Quality Checklist

\- Each rule must have a unique, descriptive identifier (e.g., `Trojan\_Generic\_ObfuscatedPS1`).

\- Include metadata block: author, date, description, reference/source, severity.

\- Prefer hex byte patterns for binary signatures; use regex only when necessary due to performance cost.

\- Test every new rule against a known-clean corpus to check for false positives before merging into signatures.db.



\## Versioning

\- Tag each signature update with a version string and timestamp in a companion manifest file.

\- Never silently overwrite an existing rule ID — deprecate and replace with a new ID plus changelog entry.

