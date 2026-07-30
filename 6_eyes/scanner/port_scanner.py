import socket
from concurrent.futures import ThreadPoolExecutor
import config
import service_detector


def scan_ports(ip,port,version):


    family = socket.AF_INET if version == 4 else socket.AF_INET6

    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(config.TIMEOUT)

    try:
        address = socket.getaddrinfo(
            ip,
            port,
            family,
            socket.SOCK_STREAM
            )[0][4]

        result = sock.connect_ex(address)

        if result == 0 :
            return True
        else:
            return False
    finally:
        sock.close()


def _scan_and_identify(ip, port, version, hostname=None):
    if scan_ports(ip, port, version):
        return service_detector.detect_and_identify(ip, port, version, hostname)
    else:
        return {
            "port": port,
            "state": "CLOSED",
            "banner": None,
            "default_service": service_detector.known_port_detection(port),
            "service": None
        }


def single_port(ip, port, version, hostname=None):
    return [_scan_and_identify(ip, port, version, hostname)]


def common_port(ip, ports, version, hostname=None):
    # Use max_workers=50 or len(ports) to scan concurrently
    max_workers = min(50, len(ports)) if len(ports) > 0 else 1
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = list(executor.map(lambda p: _scan_and_identify(ip, p, version, hostname), ports))
    return results


def custom_range(ip, start_port, end_port, version, hostname=None):
    results = []

    if start_port < 1 or end_port > 65535 or start_port > end_port:
        print("Invalid Port Range")
        return results

    ports = list(range(start_port, end_port + 1))
    max_workers = min(100, len(ports)) if len(ports) > 0 else 1
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = list(executor.map(lambda p: _scan_and_identify(ip, p, version, hostname), ports))
    return results
    