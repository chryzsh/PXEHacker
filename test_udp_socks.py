#!/usr/bin/env python3
"""Quick tests to verify SOCKS5 UDP relay and PXE server reachability."""

import sys
import struct
import socket
import binascii

sys.path.insert(0, '/home/chrisr/share/dev/PXEHacker')
from lib.socks import SOCKS5Client

def build_dns_query(domain):
    header = struct.pack('>HHHHHH', 0x1337, 0x0100, 1, 0, 0, 0)
    question = b''
    for label in domain.split('.'):
        question += bytes([len(label)]) + label.encode()
    question += b'\x00'
    question += struct.pack('>HH', 1, 1)
    return header + question

def parse_dns_response(data):
    txid = struct.unpack('>H', data[0:2])[0]
    flags = struct.unpack('>H', data[2:4])[0]
    ancount = struct.unpack('>H', data[6:8])[0]
    rcode = flags & 0xF
    rcodes = {0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 5: 'REFUSED'}
    return f"txid=0x{txid:04x}, rcode={rcodes.get(rcode, rcode)}, answers={ancount}"

def build_bootp_packet(client_ip):
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

    # Test 1: DNS to the DNS server (baseline)
    print(f"\n--- Test 1: DNS to {dns_server}:53 (baseline) ---")
    client = SOCKS5Client(socks_host, socks_port)
    try:
        client.connect()
        client.send(build_dns_query('sccm.lab'), (dns_server, 53))
        data = client.recv(4096, timeout=5)
        print(f"[+] DNS to {dns_server}: {parse_dns_response(data)}")
    except Exception as e:
        print(f"[-] Failed: {e}")
    finally:
        client.close()

    # Test 2: DNS to the PXE SERVER (can relay reach .142 at all?)
    print(f"\n--- Test 2: DNS to {pxe_server}:53 (reachability check) ---")
    client = SOCKS5Client(socks_host, socks_port)
    try:
        client.connect()
        client.send(build_dns_query('sccm.lab'), (pxe_server, 53))
        data = client.recv(4096, timeout=5)
        print(f"[+] DNS to {pxe_server}: {parse_dns_response(data)}")
    except Exception as e:
        print(f"[-] DNS to {pxe_server} failed: {e} (might not run DNS, that's ok)")

    finally:
        client.close()

    # Test 3: Send BOOTP packet to DNS server port 53 (size/relay test)
    # If the relay forwards the 314-byte BOOTP as a DNS query, we should get FORMERR back
    print(f"\n--- Test 3: Send BOOTP packet to {dns_server}:53 (does relay forward large packets?) ---")
    client = SOCKS5Client(socks_host, socks_port)
    try:
        client.connect()
        pkt = build_bootp_packet(client_ip)
        print(f"[*] Sending {len(pkt)}-byte BOOTP packet to DNS port as test")
        client.send(pkt, (dns_server, 53))
        data = client.recv(4096, timeout=5)
        print(f"[+] Got response ({len(data)} bytes) - relay forwards large packets fine")
    except Exception as e:
        print(f"[-] Failed: {e}")
    finally:
        client.close()

    # Test 4: Actual PXE request
    print(f"\n--- Test 4: BOOTP/PXE request to {pxe_server}:4011 ---")
    client = SOCKS5Client(socks_host, socks_port)
    try:
        client.connect()
        pkt = build_bootp_packet(client_ip)
        print(f"[*] ciaddr={socket.inet_ntoa(pkt[12:16])}, size={len(pkt)} bytes")
        client.send(pkt, (pxe_server, 4011))
        data = client.recv(9076, timeout=15)
        print(f"[+] Got PXE response! ({len(data)} bytes)")
    except Exception as e:
        print(f"[-] PXE failed: {e}")
    finally:
        client.close()
