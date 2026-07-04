// signatures.yar
//
// EDR-BETA signature database — ClamAV-compatible YARA rules.
//
// Hard constraints enforced across every rule (yara-signature-skill):
//   * Max 64 strings per rule (ClamAV limit)
//   * No YARA modules (pe, elf, cuckoo, etc.) — conditions use only
//     string/byte matching
//   * No precompiled yarac output — only plaintext .yar source
//   * No global rules — every rule is independently evaluable
//   * Every rule: unique descriptive ID, full metadata block,
//     hex byte patterns preferred over regex
//
// Versioning (yara-signature-skill):
//   See signatures/manifest.json for version string and timestamp.
//   Never silently overwrite an existing rule ID — deprecate and replace
//   with a new ID + changelog entry.
//
// Testing requirement (testing-security-skill):
//   Every rule below must have a corresponding test case in
//   tests/signatures/ with at minimum:
//     - one triggering (malicious/defanged) sample
//     - one non-triggering clean-file sample
//
// ============================================================================
// RULE 1 — EICAR Standard Antivirus Test File
// ============================================================================
// Purpose: Verify scanner pipeline end-to-end; EICAR is universally
// recognized and safe to distribute.  This is the canonical "does scanning
// work at all" canary.

rule EICAR_Test_File {
    meta:
        author      = "EDR-BETA Team"
        date        = "2026-07-04"
        description = "EICAR standard antivirus test string"
        reference   = "https://www.eicar.org/download-anti-malware-testfile/"
        severity    = "low"
        version     = "1.0.0"

    strings:
        // EICAR test string — exact ASCII sequence, not obfuscated
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar
}

// ============================================================================
// RULE 2 — Generic Obfuscated PowerShell Dropper
// ============================================================================
// Detects common PowerShell download-and-execute patterns used by droppers.
// Uses hex patterns for the encoded command flags to resist simple case changes.

rule Trojan_Generic_ObfuscatedPS1_Dropper {
    meta:
        author      = "EDR-BETA Team"
        date        = "2026-07-04"
        description = "Obfuscated PowerShell dropper: IEX + download-cradle pattern"
        reference   = "internal"
        severity    = "high"
        version     = "1.0.0"

    strings:
        // "IEX" variants (Invoke-Expression) — case-insensitive wide string
        $iex1 = "IEX(" nocase
        $iex2 = "Invoke-Expression" nocase

        // Download-cradle indicators
        $dl1  = "DownloadString(" nocase
        $dl2  = "DownloadFile(" nocase
        $dl3  = "WebClient" nocase
        $dl4  = "Net.WebClient" nocase
        $dl5  = "Invoke-WebRequest" nocase

        // Encoded/hidden command invocation flags (hex for resilience)
        // -EncodedCommand flag bytes: "-En" in ASCII = 2D 45 6E
        $enc1 = { 2D 45 6E 63 6F 64 65 64 43 6F 6D 6D 61 6E 64 }
        // -WindowStyle Hidden
        $enc2 = "WindowStyle Hidden" nocase
        // -NonInteractive
        $enc3 = "NonInteractive" nocase

        // Common persistence/payload hosting patterns
        $url1 = "http://" nocase
        $url2 = "https://" nocase

    condition:
        // Must have IEX + download cradle + at minimum one obfuscation signal
        (($iex1 or $iex2) and ($dl1 or $dl2 or $dl3 or $dl4 or $dl5))
        and ($enc1 or $enc2 or $enc3)
        and ($url1 or $url2)
}

// ============================================================================
// RULE 3 — Linux Reverse Shell Payload (Bash/sh)
// ============================================================================
// Detects bash-based reverse shell one-liners commonly planted by exploit
// frameworks as post-exploitation persistence.

rule Backdoor_Linux_BashReverseShell {
    meta:
        author      = "EDR-BETA Team"
        date        = "2026-07-04"
        description = "Bash reverse shell: /dev/tcp redirect to attacker IP"
        reference   = "https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet"
        severity    = "high"
        version     = "1.0.0"

    strings:
        // Classic bash /dev/tcp pattern
        $bash_tcp    = "/dev/tcp/" ascii
        $bash_udp    = "/dev/udp/" ascii

        // File descriptor redirects used in reverse shells
        $fd_redirect = ">&" ascii
        $fd_exec     = "0>&1" ascii
        $fd_exec2    = "1>&2" ascii

        // Shell spawn to inherit the socket
        $sh_spawn    = "/bin/sh" ascii
        $bash_spawn  = "/bin/bash" ascii

        // Common C2 connection strings
        $nc_e        = "nc -e" nocase
        $nc_lvp      = "nc -lvp" nocase
        $ncat        = "ncat " nocase

        // Python-based reverse shells (also common in scripts)
        $py_socket   = "import socket" ascii
        $py_subprocess = "import subprocess" ascii
        $py_connect  = ".connect((" ascii

    condition:
        (($bash_tcp or $bash_udp) and ($fd_redirect or $fd_exec or $fd_exec2)
         and ($sh_spawn or $bash_spawn))
        or ($nc_e and ($sh_spawn or $bash_spawn))
        or ($py_socket and $py_subprocess and $py_connect)
}

// ============================================================================
// RULE 4 — ELF Dropper with Embedded PE (polyglot / packer indicator)
// ============================================================================
// Detects files with both ELF and PE magic bytes — a common technique in
// cross-platform droppers.  Byte-pattern only (no pe/elf modules — ClamAV
// constraint from yara-signature-skill).

rule Dropper_Polyglot_ELF_PE_Embed {
    meta:
        author      = "EDR-BETA Team"
        date        = "2026-07-04"
        description = "File containing both ELF and PE magic headers — polyglot or embedded PE dropper"
        reference   = "internal"
        severity    = "medium"
        version     = "1.0.0"

    strings:
        // ELF magic: 7F 45 4C 46
        $elf_magic = { 7F 45 4C 46 }
        // PE magic: 4D 5A ("MZ")
        $pe_magic  = { 4D 5A }
        // PE optional magic: 50 45 00 00 ("PE\0\0")
        $pe_header = { 50 45 00 00 }

    condition:
        $elf_magic at 0
        and ($pe_magic or $pe_header)
}

// ============================================================================
// RULE 5 — Generic XOR-Encoded Shellcode Stub
// ============================================================================
// Many loaders XOR-encode their payload and decode at runtime.  This rule
// catches the decode loop stub pattern common across multiple malware families.

rule Loader_Generic_XOR_Shellcode_Stub {
    meta:
        author      = "EDR-BETA Team"
        date        = "2026-07-04"
        description = "XOR decoding loop stub indicative of encoded shellcode loader"
        reference   = "internal"
        severity    = "medium"
        version     = "1.0.0"

    strings:
        // x86-64 XOR loop: common byte patterns at stub entry
        // xor [rcx+rax], bl  — 30 19 / 30 1C 08
        $xor_loop1 = { 30 1? 0? }
        // add rax, 1 / loop dec counter
        $xor_loop2 = { 48 FF C0 }
        // jnz short -N  (loop back)
        $xor_jnz   = { 75 F? }

        // Suspicious inline key: repeated single-byte XOR key seen in many loaders
        $key_marker = { 31 C0 B0 ?? }  // xor eax,eax; mov al, <key>

        // mprotect / VirtualProtect call prep (mark region executable)
        $mprotect_prep = { B9 07 00 00 00 }  // mov ecx, 7 (PROT_READ|WRITE|EXEC)

    condition:
        2 of ($xor_loop1, $xor_loop2, $xor_jnz)
        and ($key_marker or $mprotect_prep)
}

// ============================================================================
// RULE 6 — Coinminer: XMRig Config String Pattern
// ============================================================================
// XMRig and clones embed pool configuration strings.  Matching on the
// canonical JSON field names used in XMRig's config.

rule CoinMiner_XMRig_Config_Strings {
    meta:
        author      = "EDR-BETA Team"
        date        = "2026-07-04"
        description = "XMRig cryptocurrency miner: embedded pool config JSON strings"
        reference   = "https://github.com/xmrig/xmrig"
        severity    = "medium"
        version     = "1.0.0"

    strings:
        $pool_url   = "\"pools\":" ascii
        $algo       = "\"algo\":" ascii
        $xmr_algo1  = "\"randomx\"" ascii
        $xmr_algo2  = "\"rx/0\"" ascii
        $donate     = "\"donate-level\":" ascii
        $wallet     = "\"user\":" ascii
        $tls        = "\"tls\":" ascii
        // XMRig user-agent sent to pool server
        $ua         = "XMRig/" nocase ascii

    condition:
        $ua or ($pool_url and $algo and ($xmr_algo1 or $xmr_algo2) and $donate)
}

// ============================================================================
// RULE 7 — Ransomware: File Extension Enumeration + Shadow Copy Deletion
// ============================================================================
// Ransomware pre-encryption enumerates target extensions and deletes
// Volume Shadow Copies via vssadmin/wmic to prevent recovery.

rule Ransomware_ShadowCopy_Deletion {
    meta:
        author      = "EDR-BETA Team"
        date        = "2026-07-04"
        description = "Ransomware indicator: shadow copy deletion commands embedded in file"
        reference   = "internal"
        severity    = "high"
        version     = "1.0.0"

    strings:
        // vssadmin delete shadows commands
        $vss1 = "vssadmin delete shadows" nocase ascii
        $vss2 = "vssadmin.exe Delete Shadows" nocase ascii
        // wmic shadow copy deletion
        $wmic = "wmic shadowcopy delete" nocase ascii
        // bcdedit disable recovery
        $bcd  = "bcdedit /set {default} recoveryenabled No" nocase ascii
        $bcd2 = "bcdedit.exe /set" nocase ascii
        // wbadmin delete backup catalog
        $wb   = "wbadmin delete catalog" nocase ascii

        // Common ransom note strings
        $note1 = "YOUR FILES HAVE BEEN ENCRYPTED" nocase ascii
        $note2 = "All your files are belong to us" nocase ascii
        $note3 = "HOW TO RECOVER" nocase ascii
        $note4 = ".onion" ascii

    condition:
        (2 of ($vss1, $vss2, $wmic, $bcd, $bcd2, $wb))
        or (1 of ($vss1, $vss2, $wmic) and 1 of ($note1, $note2, $note3, $note4))
}
