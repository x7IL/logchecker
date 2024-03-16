import requests

def geolocate_ip(ip_address):
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