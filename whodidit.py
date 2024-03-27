import re
from datetime import datetime

log_data = """
Mar 16 10:14:02 app-1 sshd[5142]: Accepted password for user3 from 192.168.126.1 port 62897 ssh2
Mar 16 10:14:02 app-1 sshd[5144]: pam_unix(sshd:session): session opened for user user3 by (uid=0)
Mar 16 10:14:08 app-1 custom_app: user3 performed action
Mar 16 10:14:10 app-1 sudo: user3 : TTY=pts/1 ; PWD=/home/user3 ; USER=root ; COMMAND=/bin/su
Mar 16 10:14:10 app-1 sudo: pam_unix(sudo:session): session opened for user root by user3(uid=0)
Mar 16 10:14:10 app-1 sudo: pam_unix(sudo:session): session closed for user root
"""

# Dictionnaire pour stocker les données de connexion SSH
ssh_sessions = {}

# Analyser le journal
for line in log_data.split("\n"):
    # Extraction des détails de la connexion SSH
    ssh_match = re.search(
        r"(\w+ \d+ \d+:\d+:\d+) .*Accepted password for (\w+) from ([\d.]+)", line
    )
    if ssh_match:
        timestamp_str, user, ip = ssh_match.groups()
        timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
        ssh_sessions[user] = {"ip": ip, "timestamp": timestamp}

    # Extraction de toute action après la connexion SSH
    action_match = re.search(r"(\w+ \d+ \d+:\d+:\d+) .*: (\w+) .*", line)
    if (
        action_match and not "sshd" in line
    ):  # Ignorer les lignes liées à sshd directement
        timestamp_str, user = action_match.groups()[0:2]
        timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
        action = line.split(":")[-1].strip()
        ssh_session = ssh_sessions.get(user, {"ip": "unknown", "timestamp": "unknown"})

        print(f"Action enregistrée pour {user}:")
        print(f"  IP: {ssh_session['ip']}")
        print(f"  Timestamp de connexion SSH: {ssh_session['timestamp']}")
        print(f"  Timestamp de l'action: {timestamp}")
        print(f"  Action: {action}")
        print("")
