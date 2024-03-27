import re
import csv
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
        self.log_file = log_file
        self.domain_name_cache = {}
        self.geolocation_cache = {}
        self.local_networks = [
            ("10.0.0.0", "10.255.255.255"),
            ("172.16.0.0", "172.31.255.255"),
            ("192.168.0.0", "192.168.255.255"),
        ]
        self.headers = [
            "IP Address",
            "Domain Name",
            "Country",
            "Region",
            "City",
            "Localisation",
            "Organization",
            "Postal",
            "Timezone",
            "Start Time",
            "End Time",
            "Successful Attempts",
            "Failed Attempts",
            "Total Attempts",
            "Success/failed",
            "Malicious/Not Sure/No",
            "Impacted Users",
            "Invalid Users",
            "Ports",
            "Success Details",
        ]
        self.malicious_threshold = 5
        self.batch_size = 100
        self.timeout = 5

    def is_local_ip(self, ip_address):
        ip_int = self.ip_to_int(ip_address)
        return any(
            ip_int >= self.ip_to_int(start) and ip_int <= self.ip_to_int(end)
            for start, end in self.local_networks
        )

    def ip_to_int(self, ip):
        parts = ip.split(".")
        return (
            (int(parts[0]) << 24)
            | (int(parts[1]) << 16)
            | (int(parts[2]) << 8)
            | int(parts[3])
        )

    async def get_domain_name(self, ip_address):
        if ip_address in self.domain_name_cache or self.is_local_ip(ip_address):
            return
        try:
            hostname, _, _ = await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(
                    None, socket.gethostbyaddr, ip_address
                ),
                timeout=self.timeout,
            )
            self.domain_name_cache[ip_address] = hostname
        except Exception:
            self.domain_name_cache[ip_address] = "N/A"

    async def geolocate_ip(self, ip_address, session):
        if ip_address in self.geolocation_cache or self.is_local_ip(ip_address):
            return
        try:
            async with session.get(
                f"https://ipinfo.io/{ip_address}/json", timeout=self.timeout
            ) as response:
                data = await response.json()
                self.geolocation_cache[ip_address] = {
                    "country": data.get("country", "N/A"),
                    "region": data.get("region", "N/A"),
                    "city": data.get("city", "N/A"),
                    "loc": data.get("loc", "N/A"),
                    "org": data.get("org", "N/A"),
                    "postal": data.get("postal", "N/A"),
                    "timezone": data.get("timezone", "N/A"),
                }
        except Exception as e:
            self.geolocation_cache[ip_address] = {
                "country": "N/A",
                "region": "N/A",
                "city": "N/A",
                "loc": "N/A",
                "org": "N/A",
                "postal": "N/A",
                "timezone": "N/A",
                "error": str(e),
            }

    async def resolve_addresses_batched(self, ip_addresses):
        async with aiohttp.ClientSession() as session:
            tasks = []
            for ip_address in ip_addresses:
                if ip_address not in self.domain_name_cache and not self.is_local_ip(
                    ip_address
                ):
                    tasks.append(self.get_domain_name(ip_address))
                if ip_address not in self.geolocation_cache and not self.is_local_ip(
                    ip_address
                ):
                    tasks.append(self.geolocate_ip(ip_address, session))
            await asyncio.gather(*tasks)

    def parse_auth_log(self):
        attacks, logs_by_command = {}, {}
        current_year = datetime.now().year

        with open(self.log_file, "r") as file:
            for line in file:
                date_match = re.search(r"^\w{3} \d{1,2} \d{2}:\d{2}:\d{2}", line)
                if not date_match:
                    continue

                date_str = f"{date_match.group(0)} {current_year}"
                date_time = datetime.strptime(date_str, "%b %d %H:%M:%S %Y")
                date_time_str = date_time.strftime("%Y-%m-%d %H:%M:%S")

                pid_match = re.search(r"\[(\d+)\]", line)
                pid = pid_match.group(1) if pid_match else "N/A"

                ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
                if ip_match:
                    self.process_sshd_line(ip_match, line, date_time, attacks)

                command_match = re.search(r"app-1 (\w+)", line)
                if command_match:
                    command = command_match.group(1)
                    if command not in logs_by_command:
                        logs_by_command[command] = []
                    logs_by_command[command].append((date_time_str, pid, line.strip()))

        return attacks, logs_by_command

    def process_sshd_line(self, ip_match, line, date_time, attacks):
        ip = ip_match.group(1)
        port_match = re.search(r"port (\d+)", line)
        port = port_match.group(1) if port_match else "N/A"

        user = "N/A"
        user_match = re.search(r"for (\w+) from", line)
        invalid_user_match = re.search(r"invalid user (\w+)", line)

        if user_match:
            user = user_match.group(1)
        elif invalid_user_match:
            user = invalid_user_match.group(1)

        if ip not in attacks:
            attacks[ip] = {
                "start": [date_time],
                "end": [date_time],
                "success": 0,
                "fail": 0,
                "users": set(),
                "invalid_users": set(),
                "ports": set(),
                "success_details": [],
            }
        else:
            attacks[ip]["start"].append(date_time)
            attacks[ip]["end"].append(date_time)

        attacks[ip]["ports"].add(port)
        attacks[ip]["users"].add(user)
        if invalid_user_match:
            attacks[ip]["invalid_users"].add(user)

        if "Failed password" in line:
            attacks[ip]["fail"] += 1
        elif "Accepted password" in line:
            attacks[ip]["success"] += 1
            connection_detail = (
                f"{date_time.strftime('%Y-%m-%d %H:%M:%S')}, Port: {port}, User: {user}"
            )
            attacks[ip]["success_details"].append(connection_detail)

    def apply_table_style(self, sheet):
        table_name = f"{sheet.title.replace(' ', '_')}Table"
        table_ref = f"A1:{get_column_letter(sheet.max_column)}{sheet.max_row}"
        tab = Table(displayName=table_name, ref=table_ref)
        style = TableStyleInfo(
            name="TableStyleMedium9",
            showFirstColumn=False,
            showLastColumn=False,
            showRowStripes=True,
            showColumnStripes=True,
        )
        tab.tableStyleInfo = style
        sheet.add_table(tab)

    def export_to_excel(self, attacks, logs_by_command, file_name):
        wb = Workbook()
        ws = wb.active
        ws.title = "Attack Report"

        ws.append(self.headers)
        for ip, data in attacks.items():
            domain_name = self.domain_name_cache.get(ip, "N/A")
            geo_info = self.geolocation_cache.get(
                ip,
                {
                    "country": "N/A",
                    "region": "N/A",
                    "city": "N/A",
                    "loc": "N/A",
                    "org": "N/A",
                    "postal": "N/A",
                    "timezone": "N/A",
                },
            )

            total_attempts = data["success"] + data["fail"]
            success_fail_ratio = (
                str(data["success"] / data["fail"])
                if data["fail"]
                else "N/A" if data["success"] == 0 else "1"
            )

            if data["success"] > data["fail"]:
                malicious_label = "No"
            elif data["fail"] == 0 or total_attempts < self.malicious_threshold:
                malicious_label = "Not Sure"
            else:
                malicious_label = (
                    "Yes" if data["fail"] / total_attempts > 0.9 else "Not Sure"
                )

            row = [
                ip,
                domain_name,
                geo_info.get("country", "N/A"),
                geo_info.get("region", "N/A"),
                geo_info.get("city", "N/A"),
                geo_info.get("loc", "N/A"),
                geo_info.get("org", "N/A"),
                geo_info.get("postal", "N/A"),
                geo_info.get("timezone", "N/A"),
                min(data["start"]).strftime("%Y-%m-%d %H:%M:%S"),
                max(data["end"]).strftime("%Y-%m-%d %H:%M:%S"),
                data["success"],
                data["fail"],
                total_attempts,
                success_fail_ratio,
                malicious_label,
                ", ".join(data["users"]),
                ", ".join(data["invalid_users"]),
                ", ".join(data["ports"]),
                "; ".join(data["success_details"]),
            ]
            ws.append(row)

        self.apply_table_style(ws)

        for command, logs in logs_by_command.items():
            has_pid = any(pid != "N/A" for _, pid, _ in logs)
            command_ws = wb.create_sheet(title=command.capitalize())
            headers = ["Date", "PID", "Log"] if has_pid else ["Date", "Log"]
            command_ws.append(headers)
            for log_entry in logs:
                if has_pid:
                    # Append the entire log entry as a single list when PID is included
                    command_ws.append(log_entry)
                else:
                    # When PID is not included, create and append a list from relevant parts of the log entry
                    command_ws.append([log_entry[0], log_entry[2]])  # Corrected here

            self.apply_table_style(command_ws)

        wb.save(filename=file_name)


if __name__ == "__main__":
    # Vérifie si l'argument du fichier journal est fourni.
    if len(sys.argv) < 2:
        print("Usage: python3 script.py <log_file>")
        sys.exit(1)  # Quitte le programme si aucun fichier n'est spécifié.

    # Le premier argument après le nom du script est le chemin du fichier journal.
    log_file_arg = sys.argv[1]

    # Crée une instance de AuthLogParser avec le chemin du fichier journal fourni.
    parser = AuthLogParser(log_file_arg)

    # Analyse le fichier journal pour obtenir les données des attaques et des commandes.
    attacks_data, logs_by_command = parser.parse_auth_log()

    # Résout les adresses IP pour enrichir les données des attaques avec des informations supplémentaires.
    asyncio.run(parser.resolve_addresses_batched(list(attacks_data.keys())))

    # Exporte les données analysées dans un fichier Excel.
    output_file_name = "attacks_report.xlsx"
    parser.export_to_excel(attacks_data, logs_by_command, output_file_name)

    # Affiche un message indiquant où le rapport a été enregistré.
    print(f"Report saved to {output_file_name}.")
