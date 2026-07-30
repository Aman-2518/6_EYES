import ipaddress



def validate_ip(ip):
    try:
        ip_object = ipaddress.ip_address(ip)
        return ip_object.version
    except ValueError:
        return False
