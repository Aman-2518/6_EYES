import socket
import ssl
import config


def detect_service(ip, port, version):
  
    family = socket.AF_INET if version == 4 else socket.AF_INET6

    sock = None

    try:
       
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(config.TIMEOUT)

        if port in config.HTTPS_PORTS:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=ip)


        address = socket.getaddrinfo(
            ip,
            port,
            family,
            socket.SOCK_STREAM
            )[0][4]

        sock.connect(address)

        if port in config.WEB_PORTS:
            request = config.REQUEST.format(host=ip)
            sock.sendall(request.encode())

        banner = sock.recv(config.BUFFER_SIZE)

        if not banner:
            return None

        return banner.decode(errors="ignore").strip()

    except socket.timeout:
        return None

    except ssl.SSLError as error:
        print(f"[SSL ERROR] {ip}:{port} -> {error}")

    except socket.error as error:
        print(f"[SOCKET ERROR] {ip}:{port} -> {error}")

    finally:
        if sock:
            sock.close()

    return None


def identify_service(banner,port):

    default_service = known_port_detection(port)

    if not banner:
            return default_service
      

    banner = banner.upper()

    for keyword, service in config.SERVICE_SIGNATURES.items():
        if keyword in banner:
            return service
    

    return default_service


def detect_and_identify(ip, port, version):
   
    banner = detect_service(ip, port, version)
    return {
    "port": port,
    "state": "OPEN",
    "banner": banner,
    "default_service": known_port_detection(port),
    "service": identify_service(banner, port)
    }
   

def known_port_detection(port):
    return config.KNOWN_PORT_SERVICES.get(port, "Unknown Service")
