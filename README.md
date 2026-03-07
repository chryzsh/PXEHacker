# PXEHacker

SCCM PXE exploitation tool for authorized red team and penetration testing engagements.

Merges the best of [PXEThief](https://github.com/MWR-CyberSec/PXEThief) (MWR CyberSec) and [cred1py](https://github.com/SpecterOps/cred1py) (SpecterOps) into a unified Linux-first CLI tool.

## Features

- **SOCKS5 proxy support** — Run attacks through C2 beacons (Cobalt Strike, etc.)
- **Direct UDP mode** — Local network attacks without a proxy
- **AES-128/256 auto-detection** — Handles modern SCCM deployments
- **Pure Python CMS/PKCS7** — No Windows or win32crypt dependency
- **PXE server discovery** — DHCP broadcast to find Distribution Points
- **Full attack chain** — From discovery to credential extraction
- **Offline decryption** — Process previously captured files without network access
- **Multi-algorithm deobfuscation** — 3DES, AES-128/192/256
- **Hashcat hash extraction** — Offline password cracking for protected media

## Installation

```bash
cd ~/share/dev/PXEHacker
uv venv --clear
source .venv/bin/activate
uv pip install -r requirements.txt
```

Requirements: Python 3.8+, Linux (primary platform), `uv`.

## Quick Start

### Most Common Workflow

If you already know the PXE Distribution Point IP, skip `discover`. `discover` uses DHCP broadcast and only works from the same broadcast domain.

```bash
# 1. Identify the source IP the target will see
ip route get <target_ip>

# 2. Pull the PXE media, derive/decrypt the media key, and extract variables.xml + PFX
.venv/bin/python pxehacker.py attack <target_ip> <src_ip> -o ./loot

# 3. Retrieve policies and extract credentials
# Use --mp if the management point hostname in variables.xml does not resolve on your box
.venv/bin/python pxehacker.py policies ./loot/variables.xml -o ./loot --mp http://<target_ip>
```

### PXEThief Mode 2 Equivalent

PXEHacker splits PXEThief mode `2` into two explicit commands:

```bash
.venv/bin/python pxehacker.py attack 10.112.0.142 10.111.0.111 -o ./loot
.venv/bin/python pxehacker.py policies ./loot/variables.xml -o ./loot --mp http://10.112.0.142
```

Notes:
- `attack` covers the PXE request, TFTP download, blank-password key derivation, and `variables.xml` / PFX extraction.
- `policies` uses the extracted PFX to retrieve NAA, task sequence, and collection policy data.
- PXEHacker prints the BCD path but does not download the `.boot.bcd`, because it is not needed for the credential path.

### Through SOCKS5

```bash
.venv/bin/python pxehacker.py attack <target_ip> <src_ip> <socks_host> <socks_port> -o ./loot
.venv/bin/python pxehacker.py policies ./loot/variables.xml -o ./loot --mp http://<target_ip>
```

## Subcommands

### `discover` — Find PXE servers

Sends a DHCP broadcast to discover PXE-enabled SCCM Distribution Points. Requires root for raw socket access and only works from the same broadcast domain.

```bash
sudo "$(pwd)/.venv/bin/python" pxehacker.py discover [-i INTERFACE] [-t TIMEOUT]
```

| Flag | Description |
|------|-------------|
| `-i` | Network interface (auto-detect if omitted) |
| `-t` | DHCP timeout in seconds (default: 10) |

### `attack` — PXE boot attack

Sends a crafted DHCP/PXE request to the target DP, downloads the encrypted media variables file via TFTP, and attempts decryption.

```bash
.venv/bin/python pxehacker.py attack <target> <src_ip> [socks_host socks_port] [-p PASSWORD] [-o OUTPUT]
```

| Argument | Description |
|----------|-------------|
| `target` | SCCM PXE Distribution Point IP |
| `src_ip` | Your IP address (or beacon's IP for SOCKS) |
| `socks_host` | SOCKS5 proxy host (omit for direct UDP) |
| `socks_port` | SOCKS5 proxy port (omit for direct UDP) |
| `-p` | Pre-cracked password in hex (for password-protected PXE) |
| `-o` | Output directory (default: `./loot`) |

**What happens:**
- If **no PXE password** is set: the tool derives the decryption key automatically from the DHCP response and decrypts the media file.
- If a **PXE password is set**: the tool outputs a hashcat-compatible hash for offline cracking. Re-run with `-p <cracked_hex>` after cracking.
- On success, writes `variables.xml`, PFX certificate, and `loot_summary.txt` to the output directory.
- The tool prints the BCD file path, but does not download the `.boot.bcd`.

### `decrypt` — Offline media decryption

Decrypt a previously downloaded `.boot.var` / `variables.dat` file with a known key.

```bash
.venv/bin/python pxehacker.py decrypt <file> <key_hex> [-o OUTPUT]
```

### `hash` — Extract hashcat hash

Extract a crackable hash from a password-protected media file.

```bash
.venv/bin/python pxehacker.py hash <file>
```

Output format: `$sccm$aes128$<header_hex>` or `$sccm$aes256$<header_hex>`

For AES-256 cracking, see: https://github.com/chryzsh/hashcat-6.2.6-SCCM

### `policies` — Retrieve SCCM policies

Uses the PFX certificate from decrypted media to authenticate to the SCCM Management Point and download encrypted policies.

```bash
.venv/bin/python pxehacker.py policies <variables.xml> [-o OUTPUT] [--mp URL] [--fallback-local]
```

| Flag | Description |
|------|-------------|
| `--mp` | Override the Management Point URL from the XML |
| `--fallback-local` | Also process local `.raw` blobs as fallback |
| `--fallback-input` | Input directory for fallback blobs |

**Extracts:**
- **Network Access Account** (NAA) credentials
- **Task Sequence** credentials (domain join, local admin, capture accounts)
- **Collection Variables** (often contain obfuscated secrets)

Use `--mp http://<dp_ip>` when the management point hostname in `variables.xml` does not resolve from your current host.

### `policies-local` — Offline policy decryption

Decrypt previously downloaded `.raw` policy blobs without network access.

```bash
.venv/bin/python pxehacker.py policies-local <variables.xml> [-i INPUT_DIR] [-o OUTPUT]
```

Expected files in input directory:
- `NAAConfig.raw`
- `TaskSequence_*.raw`
- `CollectionSettings.raw`

### `loot` — Extract from decrypted XML

Extract PFX certificates and variables from already-decrypted media XML.

```bash
.venv/bin/python pxehacker.py loot <variables.xml> [-o OUTPUT]
```

### `deobfuscate` — Credential deobfuscation

Deobfuscate SCCM `secret="1"` credential strings. Accepts either an XML file or a raw hex string.

```bash
# From NAAConfig XML file
.venv/bin/python pxehacker.py deobfuscate NAAConfig.xml

# From raw hex credential string
.venv/bin/python pxehacker.py deobfuscate "8913..."
```

Supports: CALG_3DES (0x6603), CALG_AES_128 (0x660E), CALG_AES_192 (0x660F), CALG_AES_256 (0x6610).

## How It Works

PXEHacker implements the SCCM CRED-1 attack path from the [Misconfiguration Manager](https://github.com/subat0mik/Misconfiguration-Manager) research.

### Attack Flow

```
┌──────────────┐     DHCP Discover     ┌──────────────┐
│  PXEHacker   │ ──────────────────>   │   SCCM DP    │
│  (attacker)  │ <──────────────────   │  (PXE server) │
│              │     DHCP Offer        │              │
│              │                       │              │
│              │   DHCP Request:4011   │              │
│              │ ──────────────────>   │              │
│              │ <──────────────────   │              │
│              │  Option 243 + 252     │              │
│              │  (var file + BCD)     │              │
│              │                       │              │
│              │     TFTP Download     │              │
│              │ ──────────────────>   │              │
│              │ <──────────────────   │              │
│              │   variables.dat       │              │
└──────┬───────┘                       └──────────────┘
       │
       │ Decrypt media variables
       │ Extract PFX certificate
       │
       │     Authenticate with PFX     ┌──────────────┐
       │ ──────────────────────────>   │  SCCM MP     │
       │ <──────────────────────────   │ (Mgmt Point) │
       │   NAA / TS / Collection       │              │
       │   Policy Blobs                │              │
       │                               └──────────────┘
       │
       │ CMS/PKCS7 Decrypt
       │ Deobfuscate credentials
       │
       ▼
   Extracted Credentials:
   - Network Access Account
   - Task Sequence passwords
   - Collection variables
```

### SOCKS5 Proxy Flow

When operating through a C2 beacon (e.g., Cobalt Strike with SOCKS proxy):

```
┌──────────┐    TCP    ┌──────────┐   UDP    ┌──────────┐
│ PXEHacker│ ───────>  │  SOCKS5  │ ──────>  │  SCCM DP │
│ (Linux)  │ <───────  │  Proxy   │ <──────  │          │
│          │           │ (Beacon) │          │          │
└──────────┘           └──────────┘          └──────────┘
```

The SOCKS5 client establishes a TCP connection for the control channel, then uses UDP ASSOCIATE to relay DHCP and TFTP traffic through the proxy.

### Encryption Details

**Media Variable File:**
- 40-byte header containing ALG_ID at offset 16 (little-endian u32)
- `0x660E` = AES-128, `0x6610` = AES-256
- Encrypted payload starts at byte 24, ends 8 bytes before EOF
- AES-CBC mode with null IV

**Key Derivation (CryptDeriveKey):**
- SHA1-based HMAC construction: `SHA1(key XOR 0x36...) || SHA1(key XOR 0x5c...)`
- Produces 40 bytes of key material
- AES-128 uses first 16 bytes, AES-256 uses first 32 bytes

**Blank Password (No PXE Password Set):**
- DHCP Option 243 Type 2 contains an encrypted key stream
- Decrypted using hardcoded key from tspxe.dll: `9F679C9B373A1F48824F3787333DE24E9`
- Bit extension algorithm converts 10-byte result to 20-byte AES key

**Policy Credential Obfuscation:**
- Supports 3DES (0x6603), AES-128 (0x660E), AES-192 (0x660F), AES-256 (0x6610)
- Same CryptDeriveKey key derivation with algorithm-specific key lengths

**CMS/PKCS7 Policy Decryption:**
- Supports RSAES-OAEP and RSA PKCS#1 v1.5 key transport
- Supports 3DES-CBC and AES-128/192/256-CBC content encryption
- Custom ASN1 DER parser (handles SCCM's SubjectKeyIdentifier which OpenSSL struggles with)

## Output Files

After a successful attack, the `./loot/` directory contains:

| File | Description |
|------|-------------|
| `variables.xml` | Decrypted media variables (PFX cert, MP URL, site code) |
| `*_SMSTSMediaPFX.pfx` | PFX client certificate for MP authentication |
| `loot_summary.txt` | Summary of extracted values and PFX password |
| `MPKEYINFORMATIONMEDIA.xml` | MP key information response |
| `ReplyAssignments.xml` | Policy assignment URLs |
| `NAAConfig.xml` | Decrypted Network Access Account policy |
| `TaskSequence_*.xml` | Decrypted task sequence policies |
| `CollectionSettings.xml` | Decrypted collection settings |
| `task_sequence_credentials.txt` | Summary of all credential fields found |

## Out of Scope (Windows-Only Features)

The following PXEThief features require Windows APIs and are not implemented:

- **Mode 6: Registry certificate extraction** — Extracts PFX from a DP's registry keys (requires local DP access)
- **Mode 7: Registry PXE password decryption** — Decrypts PXE password from DP registry

These are candidates for a future BOF (Beacon Object File) implementation.

## Credits

- [PXEThief](https://github.com/MWR-CyberSec/PXEThief) by Christopher Panayi (MWR CyberSec) — original Windows PXE attack tool
- [cred1py](https://github.com/SpecterOps/cred1py) by SpecterOps — SOCKS5-enabled CRED-1 implementation
- [pxethiefy](https://github.com/csandker/pxethiefy) by Christian Sandker — Linux port of PXEThief
- [Misconfiguration Manager](https://github.com/subat0mik/Misconfiguration-Manager) — SCCM attack research
- DEF CON 30 talk: "Pulling Passwords out of Configuration Manager"

## Provenance

This project was developed with assistance from a large language model under human direction. A human operator defined the goals, reviewed the code, chose the changes, and validated the results.

## License

This tool is for authorized security testing only. Ensure you have written authorization before using against any target.

License status is not fully settled for all upstream-derived portions of this repository:

- `PXEThief` is GPL-3.0. This repository contains code and logic derived from PXEThief.
- No license file was found in the local `cred1py` snapshot, and the upstream GitHub repository metadata did not report a license as of March 7, 2026.

See [PROVENANCE.md](./PROVENANCE.md) for the attribution and license review notes before redistributing this repository publicly.
