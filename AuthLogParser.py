import re
import sys
import asyncio
import aiohttp
import socket
from datetime import datetime
from openpyxl import Workbook
from openpyxl.worksheet.table import Table, TableStyleInfo
from openpyxl.utils import get_column_letter

class AuthLogParser:
    def __init__(self, log_file):
        # Initializes parser with log file and sets up caches and configurations.
        self.log_file = log_file
        self.domain_name_cache = {}
        self.geolocation_cache = {}
        # IP ranges for local networks.
        self.local_networks = [
            ('10.0.0.0', '10.255.255.255'),
            ('172.16.0.0', '172.31.255.255'),
            ('192.168.0.0', '192.168.255.255'),
        ]
        # Headers for the output Excel report.
        self.headers = ["IP Address", "Domain Name", "Country", "Region", "City", "Organization", "Timezone",
                        "Start Time", "End Time", "Successful Attempts", "Failed Attempts",
                        "Total Attempts", "Malicious/Not Sure/No", "Impacted Users", "Invalid Users",
                        "Ports"]
        
        self.malicious_threshold = 5  # Minimum number of attempts to flag an activity as potentially malicious.
        self.batch_size = 100 # Number of IP addresses to process in parallel during domain and geolocation lookups.
        self.timeout = 5  # Timeout for HTTP requests in seconds.

    # Checks if an IP is local.
    def is_local_ip(self, ip_address):
        # Check if the IP address is within local network ranges.
        ip_int = self.ip_to_int(ip_address)
        return any(ip_int >= self.ip_to_int(start) and ip_int <= self.ip_to_int(end) for start, end in self.local_networks)

    # Converts an IP string to an integer.
    def ip_to_int(self, ip):
        # Convert IP address string to an integer.
        parts = ip.split('.')
        return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])

    # Fetches domain name asynchronously.
    async def get_domain_name(self, ip_address):
        # Asynchronously get the domain name for an IP address.
        if ip_address in self.domain_name_cache or self.is_local_ip(ip_address):
            return
        try:
            # Execute gethostbyaddr to prevent blocking.
            hostname, _, _ = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(None, socket.gethostbyaddr, ip_address),
            timeout=self.timeout)
            self.domain_name_cache[ip_address] = hostname
        except Exception:
            # Otherwise 
            self.domain_name_cache[ip_address] = "N/A"

    # Fetches geolocation data asynchronously.
    async def geolocate_ip(self, ip_address, session):
        if ip_address in self.geolocation_cache or self.is_local_ip(ip_address):
            return
        try:
            async with session.get(f'https://ipinfo.io/{ip_address}/json', timeout=self.timeout) as response:
                data = await response.json()
                # Store timezone information along with other geolocation data.
                self.geolocation_cache[ip_address] = {
                    'country': data.get('country', 'N/A'),
                    'region': data.get('region', 'N/A'),
                    'city': data.get('city', 'N/A'),
                    'timezone': data.get('timezone', 'N/A')
                }
        except Exception as e:
            self.geolocation_cache[ip_address] = {
                'country': 'N/A', 'region': 'N/A', 'city': 'N/A', 'timezone': 'N/A', 'error': str(e)
            }
    
    # Processes IP addresses in batches for domain and geolocation data.
    async def resolve_addresses_batched(self, ip_addresses, ):
        # Resolve domain names and geolocation information in batches.
        async with aiohttp.ClientSession() as session:
            for i in range(0, len(ip_addresses), self.batch_size):
                batch = ip_addresses[i:i + self.batch_size]
                tasks = [self.get_domain_name(ip) for ip in batch] + \
                        [self.geolocate_ip(ip, session) for ip in batch]
                await asyncio.gather(*tasks)

    # Parses the log file.
    def parse_auth_log(self):
        # Stores detected attacks and other information.
        attacks, sudo_usage, other_activities = {}, {}, []
        current_year = datetime.now().year

        # Reads and processes each line of the log file.
        with open(self.log_file, 'r') as file:
            # Extracts date and IP address from the line.
            # Other details like port and user are also extracted.
            # Updates attacks data structure with this information.
            for line in file:
                date_match = re.search(r'^\w{3} \d{1,2} \d{2}:\d{2}:\d{2}', line)
                if not date_match:
                    continue

                date_str = f"{date_match.group(0)} {current_year}"
                date_time = datetime.strptime(date_str, '%b %d %H:%M:%S %Y')
                date_time_str = date_time.strftime('%Y-%m-%d %H:%M:%S')

                ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    self.process_sshd_line(ip_match, line, date_time, attacks)

                sudo_match = re.search(r'sudo:.*?(\w+) : .*?PWD=([^\s]+).*?COMMAND=(.*)', line)
                if sudo_match:
                    self.process_sudo_line(sudo_match, line, date_time_str, sudo_usage)
                elif not re.search(r'session (opened|closed) for user', line):
                    content = line[date_match.end():].strip()
                    other_activities.append((date_time_str, content))
        # After processing, returns the gathered data.
        return attacks, sudo_usage, other_activities

    # Process a line related to sshd activity.
    def process_sshd_line(self,ip_match, line, date_time, attacks):
        ip = ip_match.group(1)
        port_match = re.search(r'port (\d+)', line)
        user_match = re.search(r'for (\w+) from', line)
        invalid_user_match = re.search(r'invalid user (\w+)', line)
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

    # Process a line related to sudo usage.
    def process_sudo_line(self,sudo_match, line, date_time_str, sudo_usage):
        sudo_user = sudo_match.group(1)
        pwd = sudo_match.group(2)
        sudo_command = sudo_match.group(3).strip()
        sudo_usage.setdefault(sudo_user, []).append({
            'date': date_time_str,
            'pwd': pwd,
            'command': sudo_command
        })

    # Adds a styled table to the Excel sheet.
    def apply_table_style(self, sheet):
        # Adds and styles a table for better readability in Excel.
        table_name = f"{sheet.title.replace(' ', '_')}Table"
        table_ref = f"A1:{get_column_letter(sheet.max_column)}{sheet.max_row}"
        tab = Table(displayName=table_name, ref=table_ref)
        style = TableStyleInfo(name="TableStyleMedium9", showFirstColumn=False,
                               showLastColumn=False, showRowStripes=True, showColumnStripes=True)
        tab.tableStyleInfo = style
        sheet.add_table(tab)

    # Exports data to an Excel file.
    def export_to_excel(self, attacks, sudo_usage, other_activities, file_name):
        # Creates workbook and sheets, then populates them with data.
        # Applies table styling and saves the workbook.
        wb = Workbook()
        ws = wb.active
        ws.title = "Attack Report"

        ws.append(self.headers)

        for ip, data in attacks.items():
            domain_name = self.domain_name_cache.get(ip, 'N/A')
            geo_info = self.geolocation_cache.get(ip, {
                'country': 'N/A', 'region': 'N/A', 'city': 'N/A', 'org': 'N/A', 'timezone': 'N/A'
            })

            total_attempts = data['success'] + data['fail']
            # Determine the malicious label based on the conditions.
            if data['success'] > data['fail']:
                malicious_label = "No"
            elif total_attempts < self.malicious_threshold or data['fail'] == 0:
                malicious_label = "Not Sure"
            else:
                failure_rate = data['fail'] / total_attempts
                malicious_label = "Yes" if failure_rate > 0.9 else "Not Sure"

            row = [
                ip, domain_name, geo_info.get('country', 'N/A'), geo_info.get('region', 'N/A'),
                geo_info.get('city', 'N/A'), geo_info.get('org', 'N/A'), geo_info.get('timezone', 'N/A')
            ] + [
                min(data['start']).strftime('%Y-%m-%d %H:%M:%S'), max(data['end']).strftime('%Y-%m-%d %H:%M:%S'),
                data['success'], data['fail'], total_attempts,
                malicious_label, ', '.join(data['users']), ', '.join(data['invalid_users']),
                ', '.join(data['ports'])
            ]
            ws.append(row)

        # Apply table formatting to the attack report, and handle the remaining sheets as before.
        self.apply_table_style(ws)

        sudo_ws = wb.create_sheet("Sudo Usage")
        sudo_ws.append(["User", "Date", "PWD", "Command"])
        for user, commands in sudo_usage.items():
            for command_info in commands:
                sudo_ws.append([
                    user,
                    command_info['date'],
                    command_info['pwd'],
                    command_info['command']
                ])
        self.apply_table_style(sudo_ws)

        other_ws = wb.create_sheet("Other Activities")
        other_ws.append(["Date", "Content"])
        for date_str, content in other_activities:
            other_ws.append([date_str, content])
        self.apply_table_style(other_ws)

        wb.save(filename=file_name)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 script.py log_file")
        sys.exit(1)

    parser = AuthLogParser(sys.argv[1])
    attacks_data, sudo_usage, other_activities = parser.parse_auth_log()

    ip_addresses = list(attacks_data.keys())
    asyncio.run(parser.resolve_addresses_batched(ip_addresses))

    parser.export_to_excel(attacks_data, sudo_usage, other_activities, 'attacks_report.xlsx')
    print('Report saved to attacks_report.xlsx.')
