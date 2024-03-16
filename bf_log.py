import re
import sys
import asyncio
import aiohttp
from datetime import datetime
from openpyxl import Workbook
from openpyxl.worksheet.table import Table, TableStyleInfo
from openpyxl.utils import get_column_letter

# Caches for domain names and geolocation information to avoid redundant network requests
domain_name_cache = {}
geolocation_cache = {}

def is_local_ip(ip_address):
    """
    Determine if an IP address is within private network ranges.

    :param ip_address: IP address to check.
    :return: True if the IP is local, False otherwise.
    """
    local_networks = [
        ('10.0.0.0', '10.255.255.255'),
        ('172.16.0.0', '172.31.255.255'),
        ('192.168.0.0', '192.168.255.255'),
    ]
    ip_int = ip_to_int(ip_address)
    for start, end in local_networks:
        if ip_int >= ip_to_int(start) and ip_int <= ip_to_int(end):
            return True
    return False

def ip_to_int(ip):
    """
    Convert an IP address from string format to an integer for easier comparison.

    :param ip: IP address in string format.
    :return: Integer representation of the IP.
    """
    parts = ip.split('.')
    return int(parts[0]) << 24 | int(parts[1]) << 16 | int(parts[2]) << 8 | int(parts[3])

async def get_domain_name(ip_address):
    """
    Asynchronously retrieve the domain name associated with an IP address.

    :param ip_address: IP address to resolve.
    """
    if ip_address in domain_name_cache or is_local_ip(ip_address):
        return
    try:
        info = await asyncio.get_event_loop().getaddrinfo(ip_address, None)
        domain_name_cache[ip_address] = info[0][4][0]
    except Exception:
        domain_name_cache[ip_address] = None

async def geolocate_ip(ip_address, session):
    """
    Asynchronously geolocate an IP address using an external API.

    :param ip_address: IP address to geolocate.
    :param session: The aiohttp session used for making HTTP requests.
    """
    if ip_address in geolocation_cache or is_local_ip(ip_address):
        return
    try:
        url = f'https://ipinfo.io/{ip_address}/json'
        async with session.get(url, timeout=5) as response:
            data = await response.json()
            geolocation_cache[ip_address] = {
                'ip': ip_address,
                'country': data.get('country', 'N/A'),
                'region': data.get('region', 'N/A'),
                'city': data.get('city', 'N/A'),
            }
    except Exception as e:
        geolocation_cache[ip_address] = {'ip': ip_address, 'message': f'Error: {str(e)}'}

async def resolve_addresses(ip_addresses):
    """
    Concurrently resolve domain names and geolocations for a set of IP addresses.

    :param ip_addresses: A collection of IP addresses to resolve.
    """
    async with aiohttp.ClientSession() as session:
        tasks = [get_domain_name(ip) for ip in ip_addresses] + [geolocate_ip(ip, session) for ip in ip_addresses]
        await asyncio.gather(*tasks)

def parse_auth_log(log_file):
    """
    Parse an authentication log file to extract and aggregate attack information by IP address.

    :param log_file: Path to the log file.
    :return: A dictionary with aggregated attack data.
    """
    attacks = {}

    with open(log_file, 'r') as file:
        for line in file:
            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            date_match = re.search(r'^\w{3} \d{1,2} \d{2}:\d{2}:\d{2}', line)
            user_match = re.search(r'for (\w+) from', line)

            if ip_match and date_match:
                ip = ip_match.group(1)
                date_time = datetime.strptime(date_match.group(0), '%b %d %H:%M:%S')

                attacks.setdefault(ip, {'start': [], 'end': [], 'success': 0, 'fail': 0, 'users': set()})
                attacks[ip]['start'].append(date_time)
                attacks[ip]['end'].append(date_time)

                if user_match:
                    user = user_match.group(1)
                    attacks[ip]['users'].add(user)
                    if "Failed password" in line:
                        attacks[ip]['fail'] += 1
                    elif "Accepted password" in line:
                        attacks[ip]['success'] += 1

    return attacks

def export_to_excel(attacks, file_name):
    """
    Export the aggregated attack data to an Excel file for analysis.

    :param attacks: Aggregated attack data to export.
    :param file_name: Name of the resulting Excel file.
    """
    wb = Workbook()
    ws = wb.active
    ws.title = "Attack Report"

    headers = ["IP Address", "Domain Name", "Country", "Region", "City", "Start Time", "End Time", "Successful Attempts",
               "Failed Attempts", "Total Attempts", "Success/Failure Ratio", "Impacted Users", "Malicious"]
    ws.append(headers)

    for ip, data in attacks.items():
        domain_name = domain_name_cache.get(ip, 'N/A')
        geo_info = geolocation_cache.get(ip, {'country': 'N/A', 'region': 'N/A', 'city': 'N/A'})

        success_attempts = data['success']
        failed_attempts = data['fail']
        total_attempts = success_attempts + failed_attempts
        success_failure_ratio = 'Inf' if failed_attempts == 0 and success_attempts > 0 else round(success_attempts / failed_attempts, 2) if failed_attempts != 0 else 'N/A'

        row = [
            ip, domain_name, geo_info['country'], geo_info['region'], geo_info['city'],
            min(data['start']).strftime('%Y-%m-%d %H:%M:%S'), max(data['end']).strftime('%Y-%m-%d %H:%M:%S'),
            success_attempts, failed_attempts, total_attempts,
            success_failure_ratio, ', '.join(data['users']),
            'Yes' if success_attempts > 0 and (success_failure_ratio < 1 if isinstance(success_failure_ratio, float) else False) else 'No'
        ]
        ws.append(row)

    table_ref = f"A1:{get_column_letter(ws.max_column)}{ws.max_row}"
    tab = Table(displayName="AttackReportTable", ref=table_ref)
    style = TableStyleInfo(name="TableStyleMedium9", showRowStripes=True, showColumnStripes=True)
    tab.tableStyleInfo = style
    ws.add_table(tab)

    wb.save(filename=file_name)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 script.py log_file")
        sys.exit(1)

    log_file = sys.argv[1]
    attacks_data = parse_auth_log(log_file)

    # Resolve IP addresses before exporting to Excel
    ip_addresses = list(attacks_data.keys())
    asyncio.run(resolve_addresses(ip_addresses))

    export_to_excel(attacks_data, 'attacks_report.xlsx')
    print('Report saved to attacks_report.xlsx.')
