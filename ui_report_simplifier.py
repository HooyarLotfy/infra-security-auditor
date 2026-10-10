#!/usr/bin/env python3
"""
UI Health Report Simplifier
---------------------------
Processes the large ui_health_report.json into a clean, summarized format
focusing strictly on console errors per domain.
"""

import json
import os

def simplify_report(input_file="ui_health_report.json", output_file="ui_health_summary.json"):
    if not os.path.exists(input_file):
        print(f"[-] Error: {input_file} not found.")
        return

    print(f"[*] Simplifying {input_file}...")
    
    with open(input_file, "r") as f:
        data = json.load(f)

    simplified = {}

    for domain, domain_data in data.items():
        all_errors = []
        
        # Helper to extract errors from a page result
        def extract_page_errors(page_result):
            # 1. Capture actual JS execution errors
            for err in page_result.get("errors", []):
                all_errors.append(f"[PageError] {err}")
            
            # 2. Capture console messages of type 'error'
            for log in page_result.get("console_logs", []):
                if log.get("type") == "error":
                    all_errors.append(f"[ConsoleError] {log.get('text')}")

        # Process Home
        if "home" in domain_data:
            extract_page_errors(domain_data["home"])
            
        # Process Inner Pages
        for inner in domain_data.get("inner_pages", []):
            extract_page_errors(inner)

        # Only add to summary if there are actually errors
        if all_errors:
            # deduplicate
            simplified[domain] = list(set(all_errors))

    with open(output_file, "w") as f:
        json.dump(simplified, f, indent=4)

    print(f"[+] Simplified report generated: {output_file}")
    print(f"[*] Found issues in {len(simplified)} domains.")

if __name__ == "__main__":
    simplify_report()
