import re
from datetime import datetime
import requests

from openpyxl import Workbook
from openpyxl.worksheet.table import Table, TableStyleInfo
from openpyxl.utils import get_column_letter


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
    # Convert IP address to integer
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

def parse_auth_log(log_file):
    """Parse authentication log, aggregating data by IP with attack details."""
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
    """Export aggregated attack data to an Excel file."""
    wb = Workbook()
    ws = wb.active
    ws.title = "Attack Report"

    # Define and append headers to the Excel sheet.
    headers = ["IP Address", "Country", "Region", "City", "Start Time", "End Time", "Successful Attempts",
               "Failed Attempts", "Total Attempts", "Success/Failure Ratio", "Impacted Users", "Malicious"]
    ws.append(headers)

    # Populate the Excel sheet with attack data.
    for ip, data in attacks.items():
        start, end, success, fail = min(data['start']), max(data['end']), data['success'], data['fail']
        total_attempts = success + fail

        # Calculate ratio, handling different cases for zero failures.
        if fail == 0 and success == 0:
            ratio = 'N/A'
        elif fail == 0:
            ratio = 'Inf'
        else:
            ratio = success / fail

        # Check if ratio is numeric and less than 1 for marking as malicious.
        is_malicious = 'Yes' if isinstance(ratio, float) and ratio < 1 else 'No'

        # Get geolocation information for the IP address.
        geo_info = geolocate_ip(ip)

        # Compile row data for Excel.
        row = [
            ip, geo_info.get('country'), geo_info.get('region'), geo_info.get('city'),
            start.strftime('%Y-%m-%d %H:%M:%S'), end.strftime('%Y-%m-%d %H:%M:%S'),
            success, fail, total_attempts, ratio, ', '.join(data['users']),
            is_malicious
        ]

        ws.append(row)

    # Create, style, and append a table in the Excel sheet.
    table_ref = f"A1:{get_column_letter(ws.max_column)}{ws.max_row}"
    tab = Table(displayName="AttackReportTable", ref=table_ref)
    style = TableStyleInfo(name="TableStyleMedium9", showRowStripes=True, showColumnStripes=True)
    tab.tableStyleInfo = style
    ws.add_table(tab)

    wb.save(filename=file_name)  # Save the Excel workbook.

# Parse log, export data to Excel, and print completion message.
attacks_data = parse_auth_log('auth.log')
export_to_excel(attacks_data, 'attacks_report.xlsx')
print('Report saved to attacks_report.xlsx.')
