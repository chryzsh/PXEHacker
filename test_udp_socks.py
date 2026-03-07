#!/usr/bin/env python3
"""Quick tests to verify SOCKS5 UDP relay and PXE server reachability."""

import sys
import struct
import socket
import binascii

sys.path.insert(0, '/home/chrisr/share/dev/PXEHacker')
from lib.socks import SOCKS5Client

def build_dns_query(domain):
    """Build a simple DNS A record query."""
    header = struct.pack('>HHHHHH', 0x1337, 0x0100, 1, 0, 0, 0)
    question = b''
    for label in domain.split('.'):
        question += bytes([len(label)]) + label.encode()
    question += b'\x00'
    question += struct.pack('>HH', 1, 1)  # Type A, Class IN
    return header + question

def parse_dns_response(data):
    txid = struct.unpack('>H', data[0:2])[0]
    flags = struct.unpack('>H', data[2:4])[0]
    ancount = struct.unpack('>H', data[6:8])[0]
    rcode = flags & 0xF
    rcodes = {0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 5: 'REFUSED'}
    return f"txid=0x{txid:04x}, rcode={rcodes.get(rcode, rcode)}, answers={ancount}"

def build_bootp_packet(client_ip):
    """Build a minimal BOOTP/DHCP PXE request (same as what pxehacker sends)."""
    from scapy.layers.dhcp import BOOTP, DHCP
    pkt = BOOTP(ciaddr=client_ip, chaddr="11:22:33:44:55:66") / DHCP(options=[
        ("message-type", "request"),
        ('param_req_list', [3, 1, 60, 128, 129, 130, 131, 132, 133, 134, 135]),
        ('pxe_client_architecture', b'\x00\x00'),
        (250, binascii.unhexlify("0c01010d020800010200070e0101050400000011ff")),
        ('vendor_class_id', b'PXEClient'),
        ('pxe_client_machine_identifier', b'\x00*\x8cM\x9d\xc1lBA\x83\x87\xef\xc6\xd8s\xc6\xd2'),
        "end"])
    return bytes(pkt)

def test_dns(client, dns_server, domain='sccm.lab'):
    print(f"\n--- Test 1: DNS query for '{domain}' via {dns_server}:53 ---")
    query = build_dns_query(domain)
    client.send(query, (dns_server, 53))
    try:
        data = client.recv(4096, timeout=5)
        print(f"[+] DNS response: {parse_dns_response(data)}")
        return True
    except Exception as e:
        print(f"[-] DNS failed: {e}")
        return False

def test_pxe(client, pxe_server, client_ip):
    print(f"\n--- Test 2: BOOTP/PXE request to {pxe_server}:4011 (ciaddr={client_ip}) ---")
    pkt = build_bootp_packet(client_ip)
    print(f"[*] BOOTP packet size: {len(pkt)} bytes")
    print(f"[*] First 32 bytes: {pkt[:32].hex()}")
    # Show the ciaddr field (bytes 12-16 of BOOTP)
    print(f"[*] ciaddr in packet: {socket.inet_ntoa(pkt[12:16])}")
    client.send(pkt, (pxe_server, 4011))
    try:
        data = client.recv(9076, timeout=15)
        print(f"[+] Got PXE response! ({len(data)} bytes)")
        print(f"[+] First 32 bytes: {data[:32].hex()}")
        return True
    except Exception as e:
        print(f"[-] PXE failed: {e}")
        return False

def test_pxe_port67(client, pxe_server, client_ip):
    print(f"\n--- Test 3: BOOTP/PXE request to {pxe_server}:67 (standard DHCP port) ---")
    pkt = build_bootp_packet(client_ip)
    client.send(pkt, (pxe_server, 67))
    try:
        data = client.recv(9076, timeout=10)
        print(f"[+] Got DHCP response! ({len(data)} bytes)")
        return True
    except Exception as e:
        print(f"[-] DHCP port 67 failed: {e}")
        return False

if __name__ == '__main__':
    if len(sys.argv) < 5:
        print(f"Usage: {sys.argv[0]} <socks_host> <socks_port> <pxe_server> <client_ip> [dns_server]")
        print(f"Example: {sys.argv[0]} 10.111.0.58 9090 10.112.0.142 10.112.0.112 10.112.0.141")
        sys.exit(1)

    socks_host = sys.argv[1]
    socks_port = int(sys.argv[2])
    pxe_server = sys.argv[3]
    client_ip = sys.argv[4]
    dns_server = sys.argv[5] if len(sys.argv) > 5 else pxe_server

    # Each test needs its own SOCKS connection (relay port changes)
    # Test 1: DNS (proves relay works)
    print(f"[*] Connecting to SOCKS5 proxy {socks_host}:{socks_port}")
    client = SOCKS5Client(socks_host, socks_port)
    try:
        client.connect()
        print(f"[+] SOCKS5 UDP relay established")
        test_dns(client, dns_server)
    except Exception as e:
        print(f"[-] SOCKS5 setup failed: {e}")
        sys.exit(1)
    finally:
        client.close()

    # Test 2: PXE on port 4011
    client = SOCKS5Client(socks_host, socks_port)
    try:
        client.connect()
        test_pxe(client, pxe_server, client_ip)
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        client.close()

    # Test 3: Try standard DHCP port 67 as fallback
    client = SOCKS5Client(socks_host, socks_port)
    try:
        client.connect()
        test_pxe_port67(client, pxe_server, client_ip)
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        client.close()
