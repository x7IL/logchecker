import socket

def is_local_ip(ip_address):
    local_networks = [
        ('10.0.0.0', '10.255.255.255'),
        ('172.16.0.0', '172.31.255.255'),
        ('192.168.0.0', '192.168.255.255')
    ]
    ip_int = ip_to_int(ip_address)
    for start, end in local_networks:
        if ip_int >= ip_to_int(start) and ip_int <= ip_to_int(end):
            return True
    return False

def ip_to_int(ip):
    parts = ip.split('.')
    return int(parts[0]) << 24 | int(parts[1]) << 16 | int(parts[2]) << 8 | int(parts[3])

def get_domain_names(ip_address):
    if is_local_ip(ip_address):
        return None  # Return None for local IP addresses
    try:
        domain_names = socket.gethostbyaddr(ip_address)
        return domain_names
    except socket.herror as e:
        return None

if __name__ == "__main__":
    ip_address = "146.59.152.118"
    domain_names = get_domain_names(ip_address)

    if domain_names:
        print(f"Domain names associated with IP address {ip_address} :")
        for domain_name in domain_names:
            print(domain_name)
    else:
        print(f"No domain name found for IP address {ip_address}")
