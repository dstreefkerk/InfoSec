"""
Sigma Rules to Excel Exporter
-----------------------------

This script clones the SigmaHQ rules repository from GitHub, checks for the latest release,
parses all Sigma rule YAML files, and exports relevant rule information into an Excel (.xlsx) file. 
The output file is named using the format: 'latest_sigma_rules_as_at_<day>_<month>_<year>.xlsx'.

Features:
- Checks for the latest Sigma release using the GitHub API, with optional skipping if 
  rate limits are exceeded.
- Recursively parses all YAML files in the 'rules' directory using the '*.yml' pattern.
- Extracts important fields such as title, id, status, description, author, logsource information, 
  MITRE ATT&CK tags, and more.
- Handles certain errors gracefully and provides detailed logs.
- Deletes the existing output file if present before exporting new data.
- Automatically handles GitHub API rate limiting by waiting until the reset time if under 5 minutes; 
  otherwise, skips the update check.

Usage:
- Ensure git and Python dependencies are installed.
- Run the script directly: `python script_name.py`
- The output file will be saved in the current directory with a timestamped filename.

Requirements:
- git (for cloning the repository)
- pandas, pyyaml, requests (Python libraries)

Author: Daniel Streefkerk
Version: 1.4.3
Date: 21 February 2025
"""
import sys
import os
import time
from datetime import datetime
import subprocess
from pathlib import Path
import yaml
import pandas as pd
import requests

# Define paths and URLs
REPO_URL = "https://github.com/SigmaHQ/sigma.git"
RULES_DIR = "sigma/rules"
GITHUB_RELEASE_API = "https://api.github.com/repos/SigmaHQ/sigma/releases/latest"
OUTPUT_FILE = f"latest_sigma_rules_as_at_{datetime.now().strftime('%d_%m_%Y')}.xlsx"

print("Starting Sigma Rules to Excel Exporter...")

def check_requirements() -> None:
    """
    Checks if required dependencies (git) are installed.
    Exits the script with an error message if a requirement is missing.
    """
    print("Checking for required dependencies...")
    if subprocess.call(["git", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
        sys.exit("Error: 'git' is not installed or not found in the system PATH.")
    print("All required dependencies are installed.")


def check_for_latest_release(max_retries: int = 5) -> str:
    """
    Checks the latest release of the Sigma repository using the GitHub API.

    :param max_retries: The maximum number of retries in case of request failures.
    :return: The latest release tag or 'skipped' if the rate limit prevents checking.
    """
    print("Checking for the latest Sigma release via GitHub API...")
    retries = 0
    while retries < max_retries:
        try:
            response = requests.get(GITHUB_RELEASE_API)
            if response.status_code == 403 and 'X-RateLimit-Remaining' in response.headers and response.headers['X-RateLimit-Remaining'] == '0':
                reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
                wait_time = max(0, reset_time - int(time.time())) + 1
                if wait_time > 300:
                    print(f"GitHub API rate limit exceeded. Skipping update check as the reset is in {wait_time} seconds (>5 minutes). Proceeding without updating the repository.")
                    return "skipped"
                reset_time_str = datetime.fromtimestamp(reset_time).strftime('%H:%M:%S')
                print(f"GitHub API rate limit exceeded. Waiting {wait_time} seconds until reset at {reset_time_str}...")
                time.sleep(wait_time)
                continue
            response.raise_for_status()
            latest_release = response.json().get('tag_name', 'unknown')
            print(f"Latest Sigma release found: {latest_release}")
            return latest_release
        except requests.RequestException as e:
            print(f"Error fetching latest Sigma release (Attempt {retries + 1}/{max_retries}): {e}")
            retries += 1
            time.sleep(2 ** retries)
    sys.exit("Error: Failed to fetch the latest Sigma release after multiple attempts.")


def clone_or_update_sigma_repo(repo_url: str, latest_release: str, clone_dir: str = "sigma") -> None:
    """
    Clones or updates the Sigma repository to the latest release if available.
    """
    try:
        if not Path(clone_dir).exists():
            print("Cloning the Sigma repository...")
            subprocess.run(["git", "clone", repo_url], check=True)
        else:
            current_tag = subprocess.check_output(["git", "-C", clone_dir, "describe", "--tags"], text=True).strip()
            if current_tag == latest_release:
                print("The local Sigma repository is already up-to-date. No updates needed.")
                return
            print(f"Updating Sigma repository to the latest release: {latest_release}")
            subprocess.run(["git", "-C", clone_dir, "pull"], check=True)
        print("Repository is ready.")
    except subprocess.CalledProcessError as e:
        sys.exit(f"Error: Failed to clone or update the repository. Details: {e}")

# Function to extract relevant attributes from Sigma rule YAML
def extract_relevant_fields(rule_data: dict, file_path: str) -> dict:
    return {
        'title': rule_data.get('title'),
        'id': rule_data.get('id'),
        'status': rule_data.get('status'),
        'description': rule_data.get('description'),
        'author': rule_data.get('author'),
        'date': str(rule_data.get('date')),
        'modified': str(rule_data.get('modified')),
        'logsource_category': rule_data.get('logsource', {}).get('category'),
        'logsource_product': rule_data.get('logsource', {}).get('product'),
        'mitre_attack': ', '.join(rule_data.get('tags', [])),
        'level': rule_data.get('level'),
        'file_path': file_path
    }

# Function to parse all Sigma rule YAML files and export them to an Excel file
def parse_rules_to_excel(rules_dir: str, output_file: str) -> None:
    # Delete the file if it already exists
    if os.path.exists(output_file):
        os.remove(output_file)
        print(f"Deleted existing file: {output_file}")

    all_rules = []
    for rule_path in Path(rules_dir).rglob("*.yml"):
        try:
            print(f"Parsing {rule_path}")
            with open(rule_path, "r", encoding="utf-8") as f:
                rule_data = yaml.safe_load(f)
                all_rules.append(extract_relevant_fields(rule_data, str(rule_path)))
        except Exception as e:
            print(f"Failed to parse {rule_path}: {e}")

    df = pd.DataFrame(all_rules)
    df.to_excel(output_file, index=False)
    full_output_path = Path(output_file).resolve()
    print(f"Exported {len(all_rules)} rules to {full_output_path}")

if __name__ == '__main__':
    check_requirements()
    latest_release = check_for_latest_release()
    if latest_release != "skipped":
        clone_or_update_sigma_repo(REPO_URL, latest_release)
    else:
        print("Proceeding without updating the local Sigma repository.")
    parse_rules_to_excel(RULES_DIR, OUTPUT_FILE)
    print("All steps completed successfully!")
