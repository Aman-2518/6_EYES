from urllib.parse import urlparse
import socket

def normalize_url(url):
    url = url.strip()
    if url.startswith("http://") or url.startswith("https://"):
        return url
    else :
        return "https://"+url
    

def validate_url(url):
    url = normalize_url(url)
    parsed = urlparse(url)
    if parsed.hostname and parsed.scheme :
        return {
            "valid": True,
            "url": url,
            "scheme": parsed.scheme,
            "hostname": parsed.hostname
        }
    return {
        "valid": False,
        "error": "Invalid URL"
    }

def resolve_domain(url):
    address = []
    dns = validate_url(url)
    if not dns['valid']:
        return {
            "valid": False,
            "error": dns.get("error", "Invalid URL")
        }
    try:
        result = socket.getaddrinfo(dns['hostname'],None)
    except socket.gaierror :
        return {
            "valid": False,
            "error": "Unable to resolve domain."
        }
    seen = set()
    for info in result :
        family = info[0]
        ip = info[4][0]
        
        if family == socket.AF_INET :
            version = 4
        elif family == socket.AF_INET6:
            version = 6 
        else :
            continue  
        if ip in seen :
            continue
        seen.add(ip)
        address.append(
            {
            'ip' : ip,
            'version' : version,
            'hostname': dns["hostname"]

            }
        )
    return {
        "valid": True,
        "url": dns["url"],
        "hostname": dns["hostname"],
        "addresses": address
    }