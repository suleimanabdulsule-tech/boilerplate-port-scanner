import ipaddress
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

from common_ports import ports_and_services


def get_open_ports(target, port_range, verbose=False):
    target = target.strip()

    try:
        literal = ipaddress.ip_address(target)
        host = str(literal)
    except ValueError:
        try:
            url = target if "://" in target else f"//{target}"
            host = urlsplit(url).hostname or ""
        except ValueError:
            if ":" in target:
                return "Error: Invalid IP address"
            return "Error: Invalid hostname"

        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            if ":" in host or re.fullmatch(r"[0-9.]+", host):
                return "Error: Invalid IP address"
            literal = None

    if not host:
        return "Error: Invalid hostname"

    try:
        addresses = socket.getaddrinfo(host, 0, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        if literal is not None:
            return "Error: Invalid IP address"
        return "Error: Invalid hostname"

    family, sock_type, protocol, _, address = next(
        (entry for entry in addresses if entry[0] == socket.AF_INET),
        addresses[0],
    )
    ip = address[0]

    def scan_port(port):
        endpoint = (ip, port, *address[2:])
        try:
            with socket.socket(family, sock_type, protocol) as connection:
                connection.settimeout(1.0)
                return connection.connect_ex(endpoint) == 0
        except OSError:
            return False

    first, last = port_range
    ports = range(first, last + 1)
    with ThreadPoolExecutor(max_workers=32) as executor:
        open_ports = [
            port for port, is_open in zip(ports, executor.map(scan_port, ports))
            if is_open
        ]

    if not verbose:
        return open_ports

    if literal is None:
        label = f"{host} ({ip})"
    else:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except OSError:
            hostname = ip
        label = f"{hostname} ({ip})" if hostname != ip else ip

    lines = [f"Open ports for {label}", "PORT     SERVICE"]
    for port in open_ports:
        lines.append(f"{port:<9}{ports_and_services.get(port, 'unknown')}")

    return "\n".join(lines)