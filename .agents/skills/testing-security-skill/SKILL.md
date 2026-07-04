\---

name: testing-security-skill

description: Use when writing tests for the antivirus daemon or backend — covers fuzzing, CTF-style detection validation, and security regression testing.

\---



\# Security Testing Conventions



\## Purpose

Validate that the daemon's file-parsing and detection logic hold up under adversarial input, leveraging CTF-style test case design.



\## Fuzzing Requirements

\- Fuzz all file-parsing entry points in av-daemon (signature matcher, file header parsers) using cargo-fuzz with libFuzzer.

\- Track fuzzing corpus growth over time; new crashes must produce a regression test before being marked resolved.



\## Detection Validation

\- Build a test corpus of known-malicious samples (safely defanged/EICAR-style) and known-clean samples to measure true/false positive rates per signature.

\- Every new YARA rule requires at least one passing detection test and one non-triggering clean-file test before merge.



\## API Security Testing

\- Test backend endpoints for common web vulnerabilities relevant to your prior CTF work: XSS in dashboard fields, SQL injection in query params, XXE if any XML parsing exists, and auth bypass via token manipulation.

\- Automate these as part of CI so regressions are caught before deployment.



\## Pitfalls

\- Never run fuzzing or malware-sample tests against production quarantine/signature paths — isolate to a sandboxed test environment.

