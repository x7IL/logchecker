# AuthLogParser

**forensic assignment at ESIEA**

## Overview

**AuthLogParser** is a Python script designed to parse and analyze authentication logs, identifying potential security threats such as brute-force attacks. It extracts relevant data from the log file, resolves IP addresses to domain names and geolocations, and outputs the results into a structured Excel report.

## Prerequisites

- Python 3
- aiohttp library
- openpyxl library

### Install the required Python libraries using pip:

```
pip install aiohttp openpyxl
```

## Usage instructions:

### 1. Basic Execution:

To run the script, you need to provide the authentication log file as an argument. The script assumes the log file is formatted similarly to typical Linux authentication logs (e.g., /var/log/auth.log).

```
python3 AuthLogParser.py /path/to/auth.log
```

After execution, the script will generate an Excel file (attacks_report.xlsx) in the same directory containing the parsed and analyzed data.


### 2 Understanding the Output:

The Excel report consists of three sheets:

- Attack Report: Summarizes each detected potential attack attempt, including IP addresses, domain names, geolocations, and various statistics regarding the attempts.
- Sudo Usage: Lists each sudo command executed, along with the user who executed it and the directory from which it was executed.
- Other Activities: Contains other potentially noteworthy activities extracted from the log.

### 3. Report Structure:

- The Attack Report sheet contains columns like IP Address, Domain Name, Country, Region, City, etc., which provide a detailed overview of each suspected attack instance.
- The Sudo Usage and Other Activities sheets provide insights into system usage and potential internal threats or misconfigurations.

## Script Customization

You can modify various parts of the script to suit your specific needs:

- Local Network Ranges: Adjust self.local_networks to match your internal IP address ranges, if different from the defaults.
- Timeouts: Modify self.timeout to increase or decrease the HTTP request timeout for domain and geolocation resolutions.
- Headers: Update self.headers in the AuthLogParser class to change the output structure of the Excel report.

## Troubleshooting

- Ensure the log file path is correct and the file is accessible by the script.
- Verify that all required Python libraries are installed and up to date.
- If domain name resolution or geolocation fetching is failing, check your network connection and the availability of the ipinfo.io service.

For any additional issues or contributions, please refer to the project's repository or contact me.