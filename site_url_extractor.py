#!/usr/bin/env python3
"""
CloudPanel Site URL Extractor (Read-Only)
------------------------------------------
Connects to CloudPanel and pulls a clean list of all hosted domains.
"""

import paramiko
import json
import argparse
import sys
from getpass import getpass

class URLExtractor:
    def __init__(self, host, username, password):
        self.host = host
        self.username = username
        self.password = password
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def connect(self):
        fallbacks = [(self.username, self.password)]
        if self.username != 'root':
            fallbacks.insert(0, ('root', self.password))
            
        for user, pwd in fallbacks:
            try:
                print(f"[*] Attempting to connect to {self.host} as '{user}'...")
                self.client.connect(
                    hostname=self.host,
                    username=user,
                    password=pwd,
                    timeout=15
                )
                print(f"[+] Successfully connected as '{user}'.")
                self.username = user
                return True
            except Exception:
                continue
        return False

    def exec_cmd(self, cmd):
        if self.username == 'root':
            stdin, stdout, stderr = self.client.exec_command(cmd)
        else:
            stdin, stdout, stderr = self.client.exec_command(f"sudo -S {cmd}")
            stdin.write(self.password + "\n")
            stdin.flush()
        return stdout.read().decode('utf-8').strip()

    def get_urls(self, exclude_domains=None):
        exclude_domains = exclude_domains or []
        print("[*] Filtering domains...")
        cmd = 'find /home -mindepth 3 -maxdepth 3 -type d -path "*/htdocs/*" 2>/dev/null'
        out = self.exec_cmd(cmd)
        
        if not out:
            return []
            
        domains = []
        for line in out.split('\n'):
            parts = line.split('/')
            if len(parts) >= 5:
                domain = parts[4]
                if domain not in exclude_domains:
                    domains.append(f"http://{domain}")
        
        return sorted(list(set(domains)))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-H", "--host", required=True)
    parser.add_argument("-u", "--user", default="root")
    args = parser.parse_args()
    
    password = getpass(f"Password for {args.user}@{args.host}: ")
    extractor = URLExtractor(args.host, args.user, password)
    
    if extractor.connect():
        urls = extractor.get_urls()
        with open("domains.json", "w") as f:
            json.dump(urls, f, indent=4)
        print(f"[+] Extracted {len(urls)} URLs to domains.json")
        extractor.client.close()

if __name__ == "__main__":
    main()
