"""DHCP broadcast PXE server discovery.

Ported from PXEThief's find_pxe_server() and configure_scapy_networking(),
adapted for Linux-only operation without settings.ini.
"""

import socket
import ipaddress

from scapy.all import (
    conf, srp1, bind_layers, resolve_iface,
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
                ('param_req_list', [1, 3, 6, 66, 67]),
                "end"
            ])
        )

        conf.checkIPaddr = False
        ans = srp1(pkt, timeout=timeout, verbose=0)
        conf.checkIPaddr = True

        if not ans:
            print("[-] No DHCP responses received with PXE boot options")
            return None

        dhcp_options = ans[DHCP].options
        tftp_server = _decode_network_value(
            next((opt[1] for opt in dhcp_options if isinstance(opt, tuple) and opt[0] == "tftp_server_name"), None)
        )
        boot_file = _decode_network_value(
            next((opt[1] for opt in dhcp_options if isinstance(opt, tuple) and opt[0] == "boot-file-name"), None)
        )

        # Fallback to BOOTP fields
        if tftp_server is None and ans.haslayer(BOOTP):
            bootp = ans[BOOTP]
            if bootp.siaddr and bootp.siaddr != "0.0.0.0":
                tftp_server = bootp.siaddr
            else:
                tftp_server = _decode_network_value(
                    next((opt[1] for opt in dhcp_options if isinstance(opt, tuple) and opt[0] == "server_id"), None)
                )
            if boot_file is None:
                boot_file = _decode_network_value(bootp.file)

        if tftp_server is None:
            print("[-] DHCP responded but no PXE server found in option 66, BOOTP siaddr, or server_id")
            print("[*] If you know the DP IP, use the 'attack' subcommand directly")
            return None

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
