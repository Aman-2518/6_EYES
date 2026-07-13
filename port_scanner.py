import socket
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


def single_port(ip, port, version,hostname=None):

    results = []

    if scan_ports(ip, port, version):

        results.append(
            service_detector.detect_and_identify(ip, port, version,hostname)
        )

    else:

        results.append({
            "port": port,
            "state": "CLOSED",
            "banner": None,
            "default_service": service_detector.known_port_detection(port),
            "service": None
        })

    return results


def common_port(ip, ports, version,hostname=None):

    results = []

    for port in ports:

        if scan_ports(ip, port, version):

            results.append(
                service_detector.detect_and_identify(ip, port, version, hostname)
            )

        else:

            results.append({
                "port": port,
                "state": "CLOSED",
                "banner": None,
                "default_service": service_detector.known_port_detection(port),
                "service": None
            })

    return results


def custom_range(ip, start_port, end_port, version, hostname=None):

    results = []

    if start_port < 1 or end_port > 65535 or start_port > end_port:
        print("Invalid Port Range")
        return results

    for port in range(start_port, end_port + 1):

        if scan_ports(ip, port, version):

            results.append(
                service_detector.detect_and_identify(ip, port, version, hostname)
            )

        else:

            results.append({
                "port": port,
                "state": "CLOSED",
                "banner": None,
                "default_service": service_detector.known_port_detection(port),
                "service": None
            })

    return results
    