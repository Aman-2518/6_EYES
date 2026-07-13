import socket
import ssl
import config


def detect_service(ip, port, version,hostname = None):
  
    family = socket.AF_INET if version == 4 else socket.AF_INET6

    sock = None

    try:
       
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(config.TIMEOUT)

        if port in config.HTTPS_PORTS:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname = hostname if hostname else ip)


        address = socket.getaddrinfo(
            ip,
            port,
            family,
            socket.SOCK_STREAM
            )[0][4]

        sock.connect(address)

        if port in config.WEB_PORTS:
            host = hostname if hostname else ip
            request = config.REQUEST.format(host= host)
            sock.sendall(request.encode())

        banner = sock.recv(config.BUFFER_SIZE)

        if not banner:
            return None

        banner = banner.decode(errors="ignore").strip()
        banner = banner.splitlines()[0]
        return banner

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


def detect_and_identify(ip, port, version,hostname= None):
   
    banner = detect_service(ip, port, version ,hostname)
    return {
    "port": port,
    "state": "OPEN",
    "banner": banner,
    "default_service": known_port_detection(port),
    "service": identify_service(banner, port)
    }
   

def known_port_detection(port):
    return config.KNOWN_PORT_SERVICES.get(port, "Unknown Service")
