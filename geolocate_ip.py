import requests

def is_local_ip(ip_address):
    # Define local IP address ranges
    local_networks = [
        ('10.0.0.0', '10.255.255.255'),
        ('172.16.0.0', '172.31.255.255'),
        ('192.168.0.0', '192.168.255.255')
    ]

    # Convert IP addresses to integers for comparison
    ip_int = ip_to_int(ip_address)
    
    # Check if the IP address falls within any of the local ranges
    for start, end in local_networks:
        if ip_int >= ip_to_int(start) and ip_int <= ip_to_int(end):
            return True
    return False

def ip_to_int(ip):
    # Convert IP address to integer representation
    parts = ip.split('.')
    return int(parts[0]) << 24 | int(parts[1]) << 16 | int(parts[2]) << 8 | int(parts[3])

def geolocate_ip(ip_address):
    if is_local_ip(ip_address):
        return {
            'ip': ip_address,
            'message': 'Local IP address. Geolocation not available.'
        }
    else:
        url = f'https://ipinfo.io/{ip_address}/json'
        response = requests.get(url)
        data = response.json()
        return {
            'ip': ip_address,
            'country': data.get('country'),
            'region': data.get('region'),
            'city': data.get('city'),
        }

print(geolocate_ip("8.8.8.8"))
print(geolocate_ip("192.167.1.1"))
