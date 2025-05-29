#!/usr/bin/env python3
"""
MITRE ATT&CK Version Comparison Tool
====================================

This script analyses the differences between two versions of MITRE ATT&CK framework data
and generates a comprehensive markdown report of all changes.

Purpose:
--------
Designed to work with MITRE ATT&CK Enterprise JSON files from the official STIX repository:
https://github.com/mitre-attack/attack-stix-data/tree/master/enterprise-attack

The script identifies and documents:
- New attack techniques, threat actors, malware, tools, and campaigns
- Removed objects between versions
- Modified objects and relationships
- Overall statistics and change metrics

Usage:
------
python analyse_attack_markdown.py <from_version.json> <to_version.json>

Example:
python analyse_attack_markdown.py enterprise-attack-16.1.json enterprise-attack-17.0.json

Input:
------
- Two JSON files containing MITRE ATT&CK STIX data (typically named enterprise-attack-X.Y.json)
- Files should be downloaded from the official MITRE ATT&CK STIX repository

Output:
-------
- Markdown file named: mitre_attack_changes_X.Y_to_A.B.md (where X.Y and A.B are version numbers)
- Console output showing the same information

Report Contents:
----------------
1. Version Overview - Table comparing object counts between versions
2. Major Changes Summary - Statistics on additions, removals, and modifications
3. New Attack Techniques - Full list with descriptions
4. New Threat Actors - Full list with descriptions
5. New Malware Families - Full list with descriptions
6. New Tools - Full list with descriptions
7. New Campaigns - Full list with descriptions
8. Technical Changes Summary - Relationship and modification statistics
9. Version Migration Timeline - Summary metrics

Notes:
------
- Version numbers are automatically extracted from filenames
- Descriptions are cleaned of markdown formatting for readability
- Only shows additions (new objects) - removals are counted but not listed
- Focuses on factual data without subjective analysis or recommendations

Author: Daniel Streefkerk
"""

import json
import os
import sys
import re
from collections import defaultdict
from datetime import datetime

def analyse_attack_versions_markdown(file1, file2):
    # Extract version numbers from filenames
    def extract_version(filename):
        # Try to extract version from filename like "enterprise-attack-16.1.json"
        match = re.search(r'(\d+\.\d+)', filename)
        if match:
            return match.group(1)
        return "unknown"
    
    # Clean special characters from text
    def clean_text(text):
        if not text:
            return text
        # Replace special Unicode characters with ASCII equivalents
        replacements = {
            '\u2019': "'",  # right single quotation mark
            '\u2018': "'",  # left single quotation mark
            '\u201C': '"',  # left double quotation mark
            '\u201D': '"',  # right double quotation mark
            '\u2013': '-',  # en dash
            '\u2014': '--', # em dash
            '\u2026': '...', # ellipsis
            '\u00E6': 'ae', # ae ligature
            '\u00C6': 'AE', # AE ligature
            '\u00FC': 'u',  # u with umlaut
            '\u00DC': 'U',  # U with umlaut
            '\u00F6': 'o',  # o with umlaut
            '\u00D6': 'O',  # O with umlaut
            '\u00E4': 'a',  # a with umlaut
            '\u00C4': 'A',  # A with umlaut
            '\u00DF': 'ss', # German sharp s
            '\u00F1': 'n',  # n with tilde
            '\u00D1': 'N',  # N with tilde
        }
        for unicode_char, ascii_char in replacements.items():
            text = text.replace(unicode_char, ascii_char)
        return text
    
    version1 = extract_version(file1)
    version2 = extract_version(file2)
    
    # Read both JSON files
    print(f"Reading MITRE ATT&CK files...")
    print(f"  From: {file1} (version {version1})")
    print(f"  To: {file2} (version {version2})")
    
    with open(file1, 'r', encoding='utf-8') as f:
        data16 = json.load(f)
    
    with open(file2, 'r', encoding='utf-8') as f:
        data17 = json.load(f)
    
    # Create ID mappings for detailed analysis
    objects16 = {obj['id']: obj for obj in data16['objects'] if 'id' in obj}
    objects17 = {obj['id']: obj for obj in data17['objects'] if 'id' in obj}
    
    # Count objects by type
    types16 = defaultdict(int)
    types17 = defaultdict(int)
    
    for obj in data16['objects']:
        types16[obj['type']] += 1
    
    for obj in data17['objects']:
        types17[obj['type']] += 1
    
    # Find new, removed, and modified objects
    ids16 = set(objects16.keys())
    ids17 = set(objects17.keys())
    
    new_ids = ids17 - ids16
    removed_ids = ids16 - ids17
    common_ids = ids16 & ids17
    
    # Check for modifications
    modified_ids = set()
    for id_ in common_ids:
        if objects16[id_].get('modified') != objects17[id_].get('modified'):
            modified_ids.add(id_)
    
    # Collect new objects by type
    new_by_type = defaultdict(list)
    for id_ in new_ids:
        obj = objects17[id_]
        new_by_type[obj['type']].append(obj)
    
    # Collect removed objects by type
    removed_by_type = defaultdict(list)
    for id_ in removed_ids:
        obj = objects16[id_]
        removed_by_type[obj['type']].append(obj)
    
    # Start generating markdown output
    output = []
    output.append(f"# MITRE ATT&CK Version {version1} to {version2} Changes Summary\n")
    
    # Version Overview
    output.append("## Version Overview\n")
    output.append(f"| Component | Version {version1} | Version {version2} | Change |")
    output.append("|-----------|--------------|--------------|--------|")
    output.append("| **Release Date** | - | - | - |")
    output.append(f"| **Total Objects** | {len(data16['objects']):,} | {len(data17['objects']):,} | {len(data17['objects']) - len(data16['objects']):+,} |")
    output.append(f"| **Attack Patterns** | {types16['attack-pattern']} | {types17['attack-pattern']} | {types17['attack-pattern'] - types16['attack-pattern']:+d} |")
    output.append(f"| **Intrusion Sets** | {types16['intrusion-set']} | {types17['intrusion-set']} | {types17['intrusion-set'] - types16['intrusion-set']:+d} |")
    output.append(f"| **Malware** | {types16['malware']} | {types17['malware']} | {types17['malware'] - types16['malware']:+d} |")
    output.append(f"| **Tools** | {types16['tool']} | {types17['tool']} | {types17['tool'] - types16['tool']:+d} |")
    output.append(f"| **Campaigns** | {types16['campaign']} | {types17['campaign']} | {types17['campaign'] - types16['campaign']:+d} |")
    output.append("")
    
    # Major Changes Summary
    output.append("## Major Changes Summary\n")
    output.append("### Overall Statistics\n")
    output.append(f"- **New Objects Added**: {len(new_ids):,}")
    output.append(f"- **Objects Removed**: {len(removed_ids):,} (primarily relationships)")
    output.append(f"- **Modified Objects**: {len(modified_ids):,}")
    output.append(f"- **Net Change**: {len(new_ids) - len(removed_ids):+d} objects\n")
    
    # New Attack Techniques
    if 'attack-pattern' in new_by_type:
        output.append(f"### New Attack Techniques ({len(new_by_type['attack-pattern'])} total)\n")
        for i, obj in enumerate(new_by_type['attack-pattern'], 1):
            name = clean_text(obj.get('name', 'N/A'))
            # Get full description
            if 'description' in obj and obj['description']:
                desc = clean_text(obj['description']).replace('\n', ' ')
                # Remove extra spaces
                desc = ' '.join(desc.split())
            else:
                desc = "Technique for adversary operations."
            output.append(f"{i}. **{name}** - {desc}")
        output.append("")
    
    # New Threat Actors
    if 'intrusion-set' in new_by_type:
        output.append(f"### New Threat Actors ({len(new_by_type['intrusion-set'])} total)\n")
        for i, obj in enumerate(new_by_type['intrusion-set'], 1):
            name = clean_text(obj.get('name', 'N/A'))
            # Get full description
            if 'description' in obj and obj['description']:
                # Remove markdown links and just get the text
                desc = clean_text(obj['description']).replace('\n', ' ')
                # Remove markdown links [text](url) and keep just the text
                desc = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', desc)
                # Remove extra spaces
                desc = ' '.join(desc.split())
            else:
                desc = "Advanced Persistent Threat group."
            output.append(f"{i}. **{name}** - {desc}")
        output.append("")
    
    # New Malware Families
    if 'malware' in new_by_type:
        output.append(f"### New Malware Families ({len(new_by_type['malware'])} total)\n")
        for i, obj in enumerate(new_by_type['malware'], 1):
            name = clean_text(obj.get('name', 'N/A'))
            # Get full description
            if 'description' in obj and obj['description']:
                # Remove markdown links and just get the text
                desc = clean_text(obj['description']).replace('\n', ' ')
                # Remove markdown links [text](url) and keep just the text
                desc = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', desc)
                # Remove extra spaces
                desc = ' '.join(desc.split())
            else:
                desc = "Malware family."
            output.append(f"{i}. **{name}** - {desc}")
        output.append("")
    
    # New Tools
    if 'tool' in new_by_type:
        output.append(f"### New Tools ({len(new_by_type['tool'])} total)\n")
        for i, obj in enumerate(new_by_type['tool'], 1):
            name = clean_text(obj.get('name', 'N/A'))
            # Get full description
            if 'description' in obj and obj['description']:
                # Remove markdown links and just get the text
                desc = clean_text(obj['description']).replace('\n', ' ')
                # Remove markdown links [text](url) and keep just the text
                desc = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', desc)
                # Remove extra spaces
                desc = ' '.join(desc.split())
            else:
                desc = "Tool for adversary operations."
            output.append(f"{i}. **{name}** - {desc}")
        output.append("")
    
    # New Campaigns
    if 'campaign' in new_by_type:
        output.append(f"### New Campaigns ({len(new_by_type['campaign'])} total)\n")
        for i, obj in enumerate(new_by_type['campaign'], 1):
            name = clean_text(obj.get('name', 'N/A'))
            # Get full description
            if 'description' in obj and obj['description']:
                # Remove markdown links and just get the text
                desc = clean_text(obj['description']).replace('\n', ' ')
                # Remove markdown links [text](url) and keep just the text
                desc = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', desc)
                # Remove extra spaces
                desc = ' '.join(desc.split())
            else:
                desc = "Campaign."
            output.append(f"{i}. **{name}** - {desc}")
        output.append("")
    
    # Technical Changes Summary
    output.append("## Technical Changes Summary\n")
    output.append(f"- **Relationships Removed**: {removed_by_type.get('relationship', []).__len__():,}")
    output.append(f"- **Relationships Added**: {new_by_type.get('relationship', []).__len__():,}")
    output.append(f"- **Objects Modified**: {len(modified_ids):,} ({len(modified_ids)*100//len(common_ids)}% of common objects)\n")
    
    # Version Migration Timeline
    output.append("## Version Migration Timeline\n")
    output.append(f"- **Version {version1} to {version2}**")
    output.append(f"- **Total Objects Changed**: {len(new_ids) + len(removed_ids):,}")
    output.append(f"- **Modification Rate**: {len(modified_ids)*100//len(common_ids)}% of common objects updated")
    
    # Write to markdown file
    output_filename = f'mitre_attack_changes_{version1}_to_{version2}.md'
    with open(output_filename, 'w', encoding='utf-8') as f:
        f.write('\n'.join(output))
    
    print(f"Markdown summary written to: {output_filename}")
    
    # Also print to console
    print('\n'.join(output))

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python analyse_attack_markdown.py <from_version.json> <to_version.json>")
        print("Example: python analyse_attack_markdown.py enterprise-attack-16.1.json enterprise-attack-17.0.json")
        sys.exit(1)
    
    file1 = sys.argv[1]
    file2 = sys.argv[2]
    
    # Check if files exist
    if not os.path.exists(file1):
        print(f"Error: File '{file1}' not found")
        sys.exit(1)
    
    if not os.path.exists(file2):
        print(f"Error: File '{file2}' not found")
        sys.exit(1)
    
    analyse_attack_versions_markdown(file1, file2)