import re
from datetime import datetime
from openpyxl import Workbook
from openpyxl.worksheet.table import Table, TableStyleInfo
from openpyxl.utils import get_column_letter

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
    headers = ["IP Address", "Start Time", "End Time", "Successful Attempts",
               "Failed Attempts", "Total Attempts", "Success/Failure Ratio", "Impacted Users", "Malicious"]
    ws.append(headers)

    # Populate the Excel sheet with attack data.
    for ip, data in attacks.items():
        start, end, success, fail = min(data['start']), max(data['end']), data['success'], data['fail']
        ratio = 'N/A' if fail == 0 and success == 0 else 'Inf' if fail == 0 else success / fail
        row = [ip, start.strftime('%Y-%m-%d %H:%M:%S'), end.strftime('%Y-%m-%d %H:%M:%S'),
               success, fail, success + fail, ratio, ', '.join(data['users']),
               'Yes' if ratio != 'N/A' and ratio < 1 else 'No']
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
