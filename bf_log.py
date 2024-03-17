import re
import sys
import asyncio
import aiohttp
from datetime import datetime
from openpyxl import Workbook
from openpyxl.worksheet.table import Table, TableStyleInfo
from openpyxl.utils import get_column_letter

# Caches for domain names and geolocation information
domain_name_cache = {}
geolocation_cache = {}

def is_local_ip(ip_address):
    local_networks = [
        ('10.0.0.0', '10.255.255.255'),
        ('172.16.0.0', '172.31.255.255'),
        ('192.168.0.0', '192.168.255.255'),
    ]
    ip_int = ip_to_int(ip_address)
    return any(ip_int >= ip_to_int(start) and ip_int <= ip_to_int(end) for start, end in local_networks)

def ip_to_int(ip):
    parts = ip.split('.')
    return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])

async def get_domain_name(ip_address):
    if ip_address in domain_name_cache or is_local_ip(ip_address):
        return
    try:
        info = await asyncio.get_event_loop().getaddrinfo(ip_address, None)
        domain_name_cache[ip_address] = info[0][4][0]
    except Exception:
        domain_name_cache[ip_address] = None

async def geolocate_ip(ip_address, session):
    if ip_address in geolocation_cache or is_local_ip(ip_address):
        return
    try:
        async with session.get(f'https://ipinfo.io/{ip_address}/json', timeout=5) as response:
            data = await response.json()
            geolocation_cache[ip_address] = data
    except Exception as e:
        geolocation_cache[ip_address] = {'error': str(e)}

async def resolve_addresses(ip_addresses):
    async with aiohttp.ClientSession() as session:
        tasks = [get_domain_name(ip) for ip in ip_addresses] + [geolocate_ip(ip, session) for ip in ip_addresses]
        await asyncio.gather(*tasks)

def parse_auth_log(log_file):
    attacks = {}
    sudo_usage = {}  # Dictionary to hold sudo command usage

    with open(log_file, 'r') as file:
        for line in file:
            # Parsing general authentication and attack details
            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            port_match = re.search(r'port (\d+)', line)
            date_match = re.search(r'^\w{3} \d{1,2} \d{2}:\d{2}:\d{2}', line)
            user_match = re.search(r'for (\w+) from', line)
            invalid_user_match = re.search(r'invalid user (\w+)', line)

            # Check and parse sudo usage
            sudo_match = re.search(r'sudo:.*?(\w+) : .*?COMMAND=(.*)', line)

            if ip_match and date_match:
                ip = ip_match.group(1)
                date_time = datetime.strptime(date_match.group(0), '%b %d %H:%M:%S')
                port = port_match.group(1) if port_match else 'N/A'

                attacks.setdefault(ip, {
                    'start': [], 'end': [], 'success': 0, 'fail': 0, 'users': set(),
                    'invalid_users': set(), 'ports': set()
                })
                attacks[ip]['start'].append(date_time)
                attacks[ip]['end'].append(date_time)
                attacks[ip]['ports'].add(port)

                if user_match:
                    user = user_match.group(1)
                    attacks[ip]['users'].add(user)
                if invalid_user_match:
                    invalid_user = invalid_user_match.group(1)
                    attacks[ip]['invalid_users'].add(invalid_user)

                if "Failed password" in line:
                    attacks[ip]['fail'] += 1
                elif "Accepted password" in line:
                    attacks[ip]['success'] += 1

            # If a sudo command execution is found, log it
            if sudo_match:
                sudo_user = sudo_match.group(1)
                sudo_command = sudo_match.group(2).strip()
                sudo_usage.setdefault(sudo_user, []).append(sudo_command)

    return attacks, sudo_usage

def export_to_excel(attacks, sudo_usage, file_name):
    wb = Workbook()
    ws = wb.active
    ws.title = "Attack Report"

    headers = ["IP Address", "Domain Name", "Country", "Region", "City", "Start Time", "End Time",
               "Successful Attempts", "Failed Attempts", "Total Attempts", "Success/Failure Ratio",
               "Impacted Users", "Invalid Users", "Ports", "Malicious"]
    ws.append(headers)

    for ip, data in attacks.items():
        domain_name = domain_name_cache.get(ip, 'N/A')
        geo_info = geolocation_cache.get(ip, {'country': 'N/A', 'region': 'N/A', 'city': 'N/A'})

        row = [
            ip, domain_name, geo_info.get('country', 'N/A'), geo_info.get('region', 'N/A'), geo_info.get('city', 'N/A'),
            min(data['start']).strftime('%Y-%m-%d %H:%M:%S'), max(data['end']).strftime('%Y-%m-%d %H:%M:%S'),
            data['success'], data['fail'], data['success'] + data['fail'],
            'Inf' if data['fail'] == 0 else round(data['success'] / data['fail'], 2),
            ', '.join(data['users']), ', '.join(data['invalid_users']), ', '.join(data['ports']),
            'No' if data['success'] >= data['fail'] else 'Yes'
        ]
        ws.append(row)

    # Apply table formatting to the attack report
    table_ref = f"A1:{get_column_letter(ws.max_column)}{ws.max_row}"
    tab = Table(displayName="AttackReportTable", ref=table_ref)
    style = TableStyleInfo(name="TableStyleMedium9", showFirstColumn=True, showRowStripes=True, showColumnStripes=True)
    tab.tableStyleInfo = style
    ws.add_table(tab)

    # Create a new worksheet for sudo usage
    sudo_ws = wb.create_sheet("Sudo Usage")

    sudo_ws.append(["User", "Commands Executed"])
    for user, commands in sudo_usage.items():
        for command in commands:
            sudo_ws.append([user, command])

    # Save the workbook
    wb.save(filename=file_name)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 script.py log_file")
        sys.exit(1)

    log_file = sys.argv[1]
    attacks_data, sudo_usage = parse_auth_log(log_file)

    # Resolve IP addresses before exporting to Excel
    ip_addresses = list(attacks_data.keys())
    asyncio.run(resolve_addresses(ip_addresses))

    export_to_excel(attacks_data, sudo_usage, 'attacks_report.xlsx')
    print('Report saved to attacks_report.xlsx.')
