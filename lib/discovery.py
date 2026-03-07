"""DHCP broadcast PXE server discovery.

Ported from PXEThief's find_pxe_server() and configure_scapy_networking(),
adapted for Linux-only operation without settings.ini.
"""

import socket
import ipaddress

from scapy.all import (
    conf, srp, bind_layers, resolve_iface,
    get_if_addr, get_if_hwaddr, get_if_raw_addr,
    Ether, IP, UDP, BOOTP, DHCP,
    inet_ntop,
)
import scapy.interfaces


def _decode_network_value(value):
    """Decode a network value (bytes or string) to a clean string, or None."""
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.rstrip(b"\0").decode("utf-8", errors="ignore")
    return value.strip() or None


def _get_dhcp_option(dhcp_options, *names):
    """Return the first DHCP option value matching any provided name."""
    for opt in dhcp_options:
        if isinstance(opt, tuple) and opt[0] in names:
            return opt[1]
    return None


def _resolve_hostname(host):
    """Resolve a hostname to an IP address. Returns the IP string or raises."""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        return socket.gethostbyname(host.strip())
    except socket.gaierror:
        raise RuntimeError(f"Cannot resolve hostname: {host}")


class PXEDiscovery:
    """Discover PXE-enabled SCCM Distribution Points on the network."""

    def __init__(self, interface=None):
        self.interface = interface
        self.client_ip = None
        self.client_mac = None

    def setup_interface(self, target_ip=None):
        """Configure Scapy networking for discovery.

        If target_ip is given, pick the interface that routes to it.
        If interface was set in constructor, use that.
        Otherwise, use the default gateway interface.
        """
        if target_ip is not None:
            ip = _resolve_hostname(target_ip)
            route_info = conf.route.route(ip, verbose=0)
            if route_info[1] == "0.0.0.0":
                raise RuntimeError(f"No route found to target host {ip}")
            conf.iface = route_info[0]

        elif self.interface is not None:
            conf.iface = self.interface

        else:
            # Auto-detect: use interface that reaches default gateway
            default_gw = conf.route.route("0.0.0.0", verbose=0)
            default_gw_ip = default_gw[2]

            if default_gw_ip != '0.0.0.0':
                conf.iface = default_gw[0]
            else:
                # Fallback: first non-loopback, non-autoconfigure interface
                loopback = ipaddress.IPv4Network('127.0.0.0/8')
                autoconf = ipaddress.IPv4Network('169.254.0.0/16')

                for iface in scapy.interfaces.get_working_ifaces():
                    raw_ip = get_if_raw_addr(iface)
                    if not raw_ip:
                        continue
                    ip = ipaddress.IPv4Address(inet_ntop(socket.AF_INET, raw_ip))
                    if ip not in loopback and ip not in autoconf:
                        conf.iface = iface
                        break

        self.client_ip = get_if_addr(conf.iface)
        self.client_mac = get_if_hwaddr(conf.iface)

        # Make Scapy aware of MECM DHCP on port 4011
        bind_layers(UDP, BOOTP, dport=4011, sport=68)
        bind_layers(UDP, BOOTP, dport=68, sport=4011)

        iface = resolve_iface(conf.iface)
        iface_desc = f" - {iface.description}" if iface.description else ""
        print(f"[+] Using interface: {iface.network_name}{iface_desc}")
        print(f"[+] Client IP: {self.client_ip}, MAC: {self.client_mac}")

    def discover(self, timeout=10):
        """Send DHCP discover broadcast and find PXE servers.

        Returns a dict with 'tftp_server' and 'boot_file' keys, or None.
        """
        print("[*] Sending DHCP Discover to find PXE boot servers...")

        pkt = (
            Ether(dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=self.client_mac) /
            DHCP(options=[
                ("message-type", "discover"),
                ("vendor_class_id", b"PXEClient"),
                ("pxe_client_architecture", b"\x00\x00"),
                ("pxe_client_machine_identifier", b"\x00*\x8cM\x9d\xc1lBA\x83\x87\xef\xc6\xd8s\xc6\xd2"),
                ('param_req_list', [1, 3, 6, 60, 66, 67, 93, 94, 97]),
                "end"
            ])
        )

        conf.checkIPaddr = False
        try:
            answered, _ = srp(pkt, timeout=timeout, multi=True, verbose=0)
        finally:
            conf.checkIPaddr = True

        if not answered:
            print("[-] No DHCP responses received with PXE boot options")
            return None

        offers = []
        for _, ans in answered:
            if not ans.haslayer(DHCP):
                continue

            dhcp_options = ans[DHCP].options
            bootp = ans[BOOTP] if ans.haslayer(BOOTP) else None
            source_ip = ans[IP].src if ans.haslayer(IP) else None
            source_port = ans[UDP].sport if ans.haslayer(UDP) else None

            tftp_server_name = _decode_network_value(
                _get_dhcp_option(dhcp_options, "tftp_server_name")
            )
            boot_file = _decode_network_value(
                _get_dhcp_option(dhcp_options, "boot-file-name")
            )
            server_id = _decode_network_value(
                _get_dhcp_option(dhcp_options, "server_id")
            )
            vendor_class = _decode_network_value(
                _get_dhcp_option(dhcp_options, "vendor_class_id")
            )

            siaddr = None
            if bootp is not None and bootp.siaddr and bootp.siaddr != "0.0.0.0":
                siaddr = bootp.siaddr

            if boot_file is None and bootp is not None:
                boot_file = _decode_network_value(bootp.file)

            tftp_server = None
            score = 0
            markers = []
            looks_like_pxe = False

            if tftp_server_name:
                tftp_server = tftp_server_name
                score += 100
                markers.append("option66")
                looks_like_pxe = True

            if boot_file:
                score += 60
                markers.append("bootfile")
                looks_like_pxe = True

            if source_port == 4011:
                score += 40
                markers.append("udp4011")
                looks_like_pxe = True

            if vendor_class and "PXE" in vendor_class.upper():
                score += 20
                markers.append("vendor_class")
                looks_like_pxe = True

            if siaddr:
                if tftp_server is None:
                    tftp_server = siaddr
                score += 10
                markers.append("siaddr")

            # Only trust server_id/source_ip when the reply already looks PXE-related.
            if tftp_server is None and server_id and looks_like_pxe:
                tftp_server = server_id
                score += 10
                markers.append("server_id")

            if tftp_server is None and source_ip and looks_like_pxe:
                tftp_server = source_ip
                markers.append("source_ip")

            offers.append({
                "source_ip": source_ip or "<unknown>",
                "server_id": server_id,
                "tftp_server": tftp_server,
                "boot_file": boot_file,
                "score": score,
                "markers": markers,
                "looks_like_pxe": looks_like_pxe,
            })

        pxe_offers = [
            offer for offer in offers
            if offer["looks_like_pxe"] and offer["tftp_server"]
        ]

        if not pxe_offers:
            seen = ", ".join(sorted({offer["source_ip"] for offer in offers})) or "<none>"
            print(f"[-] Received DHCP replies, but none looked like PXE/proxyDHCP offers")
            print(f"[*] DHCP responders seen: {seen}")
            print("[*] If you know the DP IP, use the 'attack' subcommand directly")
            return None

        pxe_offers.sort(key=lambda offer: (offer["score"], bool(offer["boot_file"])), reverse=True)
        best_offer = pxe_offers[0]

        non_pxe_sources = sorted({
            offer["source_ip"]
            for offer in offers
            if offer not in pxe_offers
        })
        if non_pxe_sources:
            print(f"[*] Ignored non-PXE DHCP replies from: {', '.join(non_pxe_sources)}")

        tftp_server = best_offer["tftp_server"]
        boot_file = best_offer["boot_file"]

        # Resolve hostname if needed
        try:
            tftp_server = _resolve_hostname(tftp_server)
        except RuntimeError as e:
            print(f"[-] {e}")
            return None

        result = {
            'tftp_server': tftp_server,
            'boot_file': boot_file or '<not provided>',
        }

        print(f"[+] PXE Server: {result['tftp_server']}")
        print(f"[+] Boot File: {result['boot_file']}")

        return result
