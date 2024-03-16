import re
from datetime import datetime

attacks = {}
log_file = "auth.log"
with open(log_file, 'r') as file:
    for line in file:
        ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
        date_match = re.search(r'^\w{3} \d{1,2} \d{2}:\d{2}:\d{2}', line)
        user_match = re.search(r'for (\w+) from', line)

        if ip_match and date_match:
            ip = ip_match.group(1)
            date_time = datetime.strptime(date_match.group(0), '%b %d %H:%M:%S')

            if ip not in attacks:
                attacks[ip] = {
                    'start': [date_time],
                    'end': [date_time],
                    'success': 0,
                    'fail': 0,
                    'users': set(),
                }
            else:
                if date_time < min(attacks[ip]['start']):
                    attacks[ip]['start'].append(date_time)
                if date_time > max(attacks[ip]['end']):
                    attacks[ip]['end'].append(date_time)

            if user_match:
                user = user_match.group(1)
                attacks[ip]['users'].add(user)

                if "Failed password" in line:
                    attacks[ip]['fail'] += 1
                elif "Accepted password" in line and "sshd" in line:
                    attacks[ip]['success'] += 1

print(attacks)