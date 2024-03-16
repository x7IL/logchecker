import re
from datetime import datetime
import requests
import sys
import socket
from openpyxl import Workbook
from openpyxl.worksheet.table import Table, TableStyleInfo
from openpyxl.utils import get_column_letter

def is_local_ip(ip_address):
    """Check if an IP address is within the local network ranges."""
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
    """Convert an IP address from string format to an integer."""
    parts = ip.split('.')
    return int(parts[0]) << 24 | int(parts[1]) << 16 | int(parts[2]) << 8 | int(parts[3])

def get_domain_names(ip_address):
    """Retrieve the domain names for a given IP address, excluding local IPs."""
    if is_local_ip(ip_address):
        return None  # Return None for local IP addresses
    try:
        host_info = socket.gethostbyaddr(ip_address)
        # Combine the primary hostname and any aliases
        domain_names = [host_info[0]] + host_info[1]
        return ','.join(domain_names)
    except socket.herror:
        return None

def geolocate_ip(ip_address):
    """Geolocate a given IP address using the ipinfo.io API."""
    if is_local_ip(ip_address):
        return {
            'ip': ip_address,
            'message': 'Local IP address. Geolocation not available.'
        }
    else:
        try:
            url = f'https://ipinfo.io/{ip_address}/json'
            response = requests.get(url, timeout=5)  # Timeout set to 5 seconds
            data = response.json()
            return {
                'ip': ip_address,
                'country': data.get('country'),
                'region': data.get('region'),
                'city': data.get('city'),
            }
        except requests.Timeout:
            return {
                'ip': ip_address,
                'message': 'Request timed out. Geolocation not available.'
            }
        except Exception as e:
            return {
                'ip': ip_address,
                'message': 'Error occurred during geolocation: ' + str(e)
            }

def parse_auth_log(log_file):
    """Parse an authentication log to aggregate data by IP with attack details."""
    attacks = {}

    with open(log_file, 'r') as file:
        for line in file:
            # Extract IP, date, and username from each log entry.
            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            date_match = re.search(r'^\w{3} \d{1,2} \d{2}:\d{2}:\d{2}', line)
            user_match = re.search(r'for (\w+) from', line)

            # Aggregate and update attack data if relevant matches are found.
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
    """Export aggregated attack data to an Excel file with detailed analysis."""
    wb = Workbook()
    ws = wb.active
    ws.title = "Attack Report"

    # Define and append headers to the Excel sheet.
    headers = ["IP Address", "Domain Name", "Country", "Region", "City", "Start Time", "End Time", "Successful Attempts",
               "Failed Attempts", "Total Attempts", "Success/Failure Ratio", "Impacted Users", "Malicious"]
    ws.append(headers)

    # Populate the Excel sheet with attack data.
    for ip, data in attacks.items():
        domain_name = get_domain_names(ip)
        geo_info = geolocate_ip(ip)

        row = [
            ip, domain_name, geo_info.get('country'), geo_info.get('region'), geo_info.get('city'),
            min(data['start']).strftime('%Y-%m-%d %H:%M:%S'), max(data['end']).strftime('%Y-%m-%d %H:%M:%S'),
            data['success'], data['fail'], data['success'] + data['fail'],
            'Inf' if data['fail'] == 0 and data['success'] > 0 else data['success'] / data['fail'] if data['fail'] != 0 else 'N/A',
            ', '.join(data['users']),
            'Yes' if isinstance(data['success'] / data['fail'] if data['fail'] != 0 else 0, float) and (data['success'] / data['fail'] if data['fail'] != 0 else 0) < 1 else 'No'
        ]

        ws.append(row)

    # Add a table with style for better readability.
    table_ref = f"A1:{get_column_letter(ws.max_column)}{ws.max_row}"
    tab = Table(displayName="AttackReportTable", ref=table_ref)
    style = TableStyleInfo(name="TableStyleMedium9", showRowStripes=True, showColumnStripes=True)
    tab.tableStyleInfo = style
    ws.add_table(tab)

    wb.save(filename=file_name)

if __name__ == "__main__":
    # Main execution: Process log file and export results to an Excel report.
    if len(sys.argv) != 2:
        print("Usage: python3 file.py file_name")
        sys.exit(1)
    log_file = sys.argv[1]
    attacks_data = parse_auth_log(log_file)
    export_to_excel(attacks_data, 'attacks_report.xlsx')
    print('Report saved to attacks_report.xlsx.')
