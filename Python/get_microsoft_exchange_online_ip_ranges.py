"""
Exchange Online Subnets Script
------------------------------

This script retrieves Exchange Online IP subnets from the Microsoft Office 365 worldwide endpoints API.
It filters only the records related to the 'Exchange' service area and outputs the collected subnets
in a formatted list to the console.

Features:
- Retrieves data from the Office 365 worldwide endpoints API.
- Filters the IP subnets specifically for Exchange Online.
- Gracefully handles request and JSON parsing errors.
- Formats the output for improved readability.

Usage:
- Ensure Python dependencies are installed (e.g., requests).
- Run the script directly: `python script_name.py`
- The output will be displayed in the console.

Requirements:
- requests (Python library)

Author: Daniel Streefkerk
Version: 1.0.0
Date: July 2023
"""

import requests

url = "https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7"

try:
    response = requests.get(url)
    response.raise_for_status()  # Check if the request was successful
    data = response.json()  # Attempt to parse JSON response
except requests.RequestException as e:
    print(f"Request failed: {e}")
    data = []
except ValueError as e:
    print(f"Invalid JSON response: {e}")
    data = []

# Initialising an empty list to store Exchange Online IP subnets
exchange_online_subnets = []

# Filter only the records related to the 'Exchange' service area
for record in data:
    if record['serviceArea'] == 'Exchange':
        ips = record.get('ips', [])  # Use empty list as the default value if 'ips' key is missing
        exchange_online_subnets.extend(ips)

# Output the collected Exchange Online subnets to the console with better formatting
print("Collected Exchange Online Subnets:")
for subnet in exchange_online_subnets:
    print(f"- {subnet}")
