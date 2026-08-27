# AGENTS.md — Working in PXEHacker as an Agent

This file is for AI coding agents (Claude Code, Codex, etc.) working in this
repository. Read it before touching code. The README is the user-facing doc;
this file is the operator's manual for working *on* the code.

## 1. What this project is

PXEHacker is a Linux-first, pure-Python merge of two upstream SCCM PXE attack
tools:

- **PXEThief** (MWR CyberSec, GPL-3.0) — the original mode-1/mode-2 reference
  implementation. Windows-centric, uses `win32crypt`, depends on `lxml`.
- **cred1py** (SpecterOps, no published license) — cleaner architecture,
  SOCKS5 support, AES-256 auto-detection, pure-Python CMS.

The intent is one tool that runs on a Kali/Linux operator box (and through a
C2 SOCKS5 channel), without `win32crypt` and without `lxml`. See the README's
lineage table for the full list of upstream/sibling projects this draws from —
none of their source trees are vendored into this repo; logic is
re-implemented and attributed in code comments.

This is built for **authorized red team / pentest engagements** against SCCM.

## 2. Repository layout

```
pxehacker.py            CLI entry point — argparse, subcommand dispatch
lib/
  sccm.py               DHCP/PXE protocol, AES-128/256 media file crypto,
                        blank-password key derivation, deobfuscation. Mostly
                        verbatim from cred1py.
  socks.py              SOCKS5Client (TCP control + UDP ASSOCIATE) and
                        DirectUDPClient. The cred1py socket-recreation bug is
                        fixed here — do not regress it.
  tftp.py               TFTP read with retry / OACK / error handling. Merged
                        from both projects.
  policy.py             MP policy retrieval, PKCS7/CMS decryption, NAA + task
                        sequence + collection variable parsing. Derived from
                        PXEThief but rewritten to use stdlib ElementTree and
                        the `cryptography` package instead of win32crypt+lxml.
  discovery.py          DHCP broadcast PXE discovery (ported from PXEThief).
requirements.txt        scapy, pycryptodome, cryptography, requests,
                        requests-toolbelt. No lxml. No pywin32.
loot/                   Operational output — gitignored. NEVER commit.
README.md               User docs, including the upstream lineage table.
```

There are no vendored reference-fork subdirectories in this repo — upstream
projects are cloned to a scratch location when needed and not committed. When porting a feature,
re-implement it in `lib/` and credit the source in a comment.

## 3. CLI subcommands (what `pxehacker.py` exposes)

| Mode             | Purpose                                                        |
|------------------|----------------------------------------------------------------|
| `discover`       | DHCP broadcast to find PXE DPs (needs root, same L2 segment)   |
| `attack`         | Full PXE flow: DHCP request -> TFTP `.var` -> derive key -> decrypt -> dump PFX + `variables.xml` |
| `decrypt`        | Offline: decrypt a `.boot.var` given the AES key in hex        |
| `derive-key`     | Offline: derive the per-media AES key from a captured DHCP option 243 type-2 cryptokey blob (blank-password media). Optional `-f` to decrypt in one step. |
| `hash`           | Extract `$sccm$aesNNN$...` hash for offline cracking           |
| `loot`           | Re-extract PFX + info from an already-decrypted variables XML  |
| `policies`       | Use the media PFX to talk to the MP and pull NAA / task sequence / collection policies, then decrypt + deobfuscate. Honours `--mp`, `--fallback-local`. |
| `policies-local` | Decrypt policy `.raw` blobs offline — no network required      |
| `deobfuscate`    | Deobfuscate `secret='1'` blobs (3DES + AES-128/192/256)        |

The CLI is the contract. When adding behaviour, prefer a new subcommand or a
flag on an existing one over silently changing a default.

## 4. Hard-won lessons (do not relearn these)

### 4.1 Blank-password key derivation has two layers
- The hardcoded key `9F679C9B373A1F48824F378733DE24E9` from `tspxe.dll` is a
  **key-encryption-key**, not the AES key for the `.var` file.
- It only unwraps the per-deployment cryptokey delivered in DHCP option 243
  sub-record type 2.
- Each PXE deployment hands out a different final AES key. If you only have a
  `.var` and a Wireshark capture, use `derive-key` against the type-2 blob to
  recover the AES key, then `decrypt`.
- See the README "Cryptographic Details" section for the README copy of this.

### 4.2 `SMSTSMP` in `variables.xml` can be a `*`-separated list
The MP variable is sometimes one URL, sometimes multiple separated by `*`. The
`policies` flow iterates candidates and tries each one. Do not collapse this
back to a single URL — sites with multiple MPs rely on the iteration.

### 4.3 MPKEYINFORMATIONMEDIA is not always callable
The `x64UnknownMachineGUID` is also baked into `variables.xml` as
`_SMSTSx64UnknownMachineGUID` (likewise x86 and arm64). The `policies` flow
prefers the local GUID and only falls back to hitting the MP. This avoids a
round trip and works against MPs that refuse `MPKEYINFORMATIONMEDIA` without
auth.

### 4.4 MPs in HTTPS / Enhanced HTTP mode want TLS client auth
The PFX from `variables.xml` is also the TLS client cert the MP expects. The
flow writes `_mp_client_cert.pem` and `_mp_client_key.pem` (mode 0600) into
the loot dir and passes them via `session.cert`. Don't ship those PEMs to the
operator's home directory or to `/tmp` — they are media-scoped credentials and
belong with the rest of the loot for that target.

### 4.5 Save raw responses on failure
`policies` writes `PolicyAssignmentsResponse.raw`, `MPKEYINFORMATIONMEDIA.xml`,
and friends *before* parsing. When the MP returns HTML or an error page,
operators need the body to diagnose. Keep this pattern when adding new MP
calls.

### 4.6 SOCKS5 UDP needs a stable socket
`cred1py`'s original SOCKS5Client recreated the UDP socket per send/recv and
that broke under any real C2 path. `lib/socks.py` keeps one bound UDP socket
for the life of the SOCKS5 association. Do not "simplify" it back.

### 4.7 No lxml, no win32crypt
Stdlib `xml.etree.ElementTree` with a parent map is enough for task-sequence
step parsing. `cryptography` + `pycryptodome` cover everything PXEThief used
`win32crypt` for. If you're about to add either dependency, find another way.

### 4.8 Windows registry credential modes (PXEThief modes 6 and 7) are out of scope
They require local registry access on a Windows MP/DP. Documented as future BOF
candidates in conversation history. Don't try to port them as Python — they
don't belong here.

### 4.9 `sccmwtf.py` (client-registration NAA harvesting) is a different tool, not a PXEHacker feature
Both `evildaemond/pxethiefup` and `blurbdust/PXEThief` bundle a `sccmwtf.py`
(originally `xpn/sccmwtf`) that registers a fake SCCM client over HTTP to pull
policies and NAA creds — no PXE, no TFTP, no DHCP involved. It was reviewed
(2026-08-20) and intentionally left out: it's a different attack surface than
this project's PXE/TFTP scope. If it's ever wanted, it belongs as a separate
tool, not bolted onto `lib/`.

### 4.10 Weak/default passwords and hashcat mode are wired together
`lib/sccm.py`'s `SCCM.try_weak_passwords()` tries the blank password plus a
short list of common defaults (ported from `pxethiefup`'s
`test_default_weak_passwords_on_media`) before `hash`/`attack` fall back to
printing a `$sccm$aes128$...`/`$sccm$aes256$...` hash. The hash output pairs
with hashcat modes `19850`/`19851` from `chryzsh/hashcat-6.2.6-SCCM` (see
`pxehacker.py`'s `HASHCAT_MODES` / `print_hashcat_command`) — don't strip the
mode number back out, operators need the ready-to-run command.

### 4.11 Credential-string obfuscation is PKCS7-padded — always unpad before decode
`lib/sccm.py`'s `SCCM.deobfuscate_credential_string()` (used by `deobfuscate`
and `deobfuscate_naa_xml`) decrypts a `secret="1"` credential blob and used to
just do `text[:text.rfind('\x00')]` to strip padding. Real SCCM credential
strings are PKCS7-padded, and PKCS7 padding bytes are essentially never
`\x00` — so that heuristic left the padding bytes decoded as garbage
characters (found: literal Thai script glyphs) appended to real passwords.
Found 2026-08-27 by testing the CLI directly with realistic PKCS7-padded
input (an earlier synthetic test had accidentally used null-byte padding,
which masked the bug). Fixed by adding `_pkcs7_unpad()` — mirrors
`lib/policy.py`'s `_deobfuscate_credential_string`, which already had this
right. If you touch either implementation, keep the unpad step; don't drop
back to the null-truncation-only heuristic.

### 4.12 MAC and PXE machine identifier are randomized per run — don't hardcode them back
`attack` used to send a literal `chaddr=11:22:33:44:55:66`, and `lib/sccm.py` /
`lib/discovery.py` both sent the exact same static 16-byte
`pxe_client_machine_identifier` (DHCP option 97) on every request. That's a
static, tool-wide fingerprint any blue team logging PXE/DHCP traffic can
trivially alert on. Both are now randomized per run (`generate_random_mac()`
in `pxehacker.py`, `os.urandom(16)` for the machine identifier in
`send_bootp_request()` and `PXEDiscovery.discover()`). `attack` also accepts
`--mac` to pin a specific MAC when an engagement requires it. Don't
reintroduce a fixed value for either.

### 4.13 `attack` and `policies` logic lives in `run_attack()` / `run_policies()`, not inline in `main()`
`main()`'s `if args.mode == "attack":` / `"policies"` blocks are thin dispatch
wrappers around `run_attack(args)` and `run_policies(args)` (both return
`True`/`False`, not `sys.exit()`). This exists so `auto` mode can call both in
sequence: `run_attack()` then, on success, build a `policies`-shaped
`argparse.Namespace` and call `run_policies()`. If you're changing attack or
policy-retrieval behavior, edit the function, not a mode block — the mode
blocks are just plumbing now. `auto` deliberately does not chain into
`policies` when `run_attack()` returns `False` (e.g. password-protected media
with no weak-password match) — there's no decrypted `variables.xml` to feed
it yet.

### 4.14 Legacy CALG_3DES cryptokey wrapping is unverified
`SCCM.derive_blank_decryption_key()` has a 3DES branch (`inner_alg_id ==
0x6603`) ported from `blurbdust/PXEThief` for older sites that wrap the
blank-password cryptokey with 3DES instead of AES. It has never been tested
against a real 3DES-wrapped capture — if a `derive-key` run against a legacy
site produces garbage, this branch is the first place to check.

## 5. Operational hygiene — the loot directory

`loot/` contains real captured credentials, decrypted task sequences, PFX
files, PEM private keys, and raw policy blobs from live engagements.

- **It is gitignored.** Keep it that way.
- Never `git add -A`, `git add .`, or `git add loot/`.
- If you generate new artifact filenames in code, add the pattern to
  `.gitignore` *first*, then write the file.
- If a user asks you to commit "everything", commit only the source changes
  and explicitly call out that loot was excluded. They will thank you.
- Don't paste loot contents into chat, PR descriptions, commit messages, or
  test fixtures.

## 6. Environment and running things

```bash
uv venv --clear
source .venv/bin/activate
uv pip install -r requirements.txt
.venv/bin/python pxehacker.py --help
```

- Python 3.8+, Linux.
- `discover` needs root and a real L2 segment — it will not work in most
  containers or over a tunnel. If the operator already knows the DP IP, skip
  it.
- `attack` against a real target requires reachability to UDP/67 + UDP/69 on
  the DP, or a SOCKS5 path that allows UDP ASSOCIATE.
- There is no test suite. `test_udp_socks.py` is a manual harness, not pytest.
  Don't claim "tests pass" — say what you actually ran.

## 7. Coding conventions

- Pure Python, stdlib-first. New deps need a justification.
- Keep `pxehacker.py` as the only CLI surface. Library code goes in `lib/`.
- The user is not a strong Python developer. Prefer clear, linear code over
  clever abstractions. One reasonable function beats three "extensible" ones.
- Print operator-facing status with the existing `[*]` / `[!]` / `[+]`
  conventions — these get read live in an engagement.
- When porting from an upstream project (see the README lineage table), leave
  a short comment naming the source so the next reader can diff against it.

## 8. Git and commits

- The user commits often. Small, focused commits are welcome.
- The default branch is `main`. The remote is `origin`
  (`github.com/chryzsh/PXEHacker`).
- Never commit `loot/`, `__pycache__/`, `.pytest_cache/`, `*.pem`, `*.pfx`,
  `*.var`, or `variables.xml`. The `.gitignore` covers these — keep it
  current.
- Do not push without an explicit ask. When the user says "commit and push",
  push to `origin/main` and nothing else.
- Conventional one-line subject + short body is fine. Match the existing log
  style (`git log --oneline`).

## 9. Shell / tool conventions (Claude Code specific)

- The user's global instructions forbid chaining shell commands with `&&`,
  `||`, `;`, or pipes inside a single Bash call. Use parallel Bash calls
  instead.
- Prefer `git -C <path>` over `cd <path> && git ...`.
- Prefer Read / Grep / Glob over `cat`, `find`, `grep`.

## 10. When in doubt

- Read `README.md` for the operator-facing flow and the upstream lineage table.
- If a behaviour seems wrong, clone the relevant upstream project (see the
  README lineage table for URLs) to a scratch location and diff against it
  before "fixing" it — don't guess.
- Ask the operator. This is a security tool; silent assumptions are worse
  than a clarifying question.
