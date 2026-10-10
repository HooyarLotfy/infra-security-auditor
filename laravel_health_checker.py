#!/usr/bin/env python3
"""
Laravel Audit Analyzer
----------------------
This script analyzes an existing 'cloudpanel_audit_report.csv' and extracts
important security issues specifically relevant to Laravel environments.
"""

import csv
import sys
import os

def analyze_report(input_file, output_file="laravel_security_issues.csv"):
    if not os.path.exists(input_file):
        print(f"[-] Error: Input file '{input_file}' not found.")
        return

    issues = []
    
    # Laravel specific interesting paths and their "Ideal" states
    # We focus on things that are CRITICAL or WARNING in the audit report
    # and specifically target Laravel structure.
    
    print(f"[*] Analyzing {input_file} for Laravel specific issues...")
    
    try:
        with open(input_file, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Filter logic:
                # 1. Any status that is CRITICAL
                # 2. Any status that is WARNING if it involves Laravel-sensitive paths
                
                target = row['target'].lower()
                status = row['status'].upper()
                
                is_laravel_path = any(x in target for x in ['.env', 'storage', 'bootstrap/cache', 'public'])
                is_critical = status == 'CRITICAL'
                is_warning = status == 'WARNING'
                
                # We specifically want to highlight:
                # - World writable anything (.perm -002 in find terms, or 777 in stat)
                # - .env with high perms
                # - Ownership issues on core Laravel dirs
                
                if is_critical or (is_warning and is_laravel_path):
                    issues.append(row)

        if not issues:
            print("[+] No major Laravel security issues detected in the report.")
            return

        # Write the filtered results
        keys = reader.fieldnames
        with open(output_file, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(issues)
            
        print(f"[+] Found {len(issues)} important issues.")
        print(f"[+] Filtered report generated: {output_file}")
        
        # summary output to terminal
        print("\n--- Quick Summary of Issues ---")
        for i in issues[:10]: # show first 10
            print(f"[{i['status']}] {i['site_name']} - {i['target']}: {i['explanation']}")
        if len(issues) > 10:
            print(f"... and {len(issues)-10} more.")

    except Exception as e:
        print(f"[-] Error during analysis: {e}")

if __name__ == "__main__":
    input_csv = "cloudpanel_audit_report.csv"
    if len(sys.argv) > 1:
        input_csv = sys.argv[1]
        
    analyze_report(input_csv)
