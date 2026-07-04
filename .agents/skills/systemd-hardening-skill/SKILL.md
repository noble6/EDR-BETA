\---

name: systemd-hardening-skill

description: Use when writing or reviewing antivirus.service — ensures the daemon runs with least-privilege sandboxing per systemd hardening best practices.

\---



\# systemd Hardening Checklist for antivirus.service



\## Purpose

Lock down the av-daemon systemd unit so a compromised daemon has minimal blast radius.



\## Required Directives

\- ProtectSystem=strict — mount the entire filesystem read-only except explicitly allowed paths \[web:5]\[web:9].

\- PrivateTmp=true — isolate /tmp from the host.

\- NoNewPrivileges=true — prevent privilege escalation via setuid binaries \[web:15].

\- ProtectHome=true — deny access to user home directories.

\- ReadWritePaths= — explicitly allow only quarantine/ and logs/ as writable.

\- CapabilityBoundingSet= — restrict to only the capabilities scanning requires (e.g., CAP\_DAC\_READ\_SEARCH), drop everything else.

\- RestrictAddressFamilies=AF\_UNIX AF\_INET AF\_INET6 — limit network access to what backend communication needs.

\- SystemCallFilter=@system-service — apply a syscall allowlist profile.



\## Validation Step

\- After writing the unit file, run `systemd-analyze security antivirus.service` and iterate until the exposure score is minimized \[web:5].

\- Document any directive intentionally left permissive (with justification) in a comment above the directive.



\## Common Pitfalls

\- Forgetting ReadWritePaths breaks quarantine writes under ProtectSystem=strict.

\- Overly broad CapabilityBoundingSet defeats the purpose of sandboxing — audit against actual syscalls the daemon needs.

