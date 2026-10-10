#!/usr/bin/env python3
"""
CloudPanel Security Auditing Script (Read-Only)
-----------------------------------------------
This script connects to a CloudPanel server via SSH and audits file permissions
and ownerships of hosted domains (/home/*/htdocs/*).

Safety Assurances:
- The script executes ONLY 'find' and 'stat' commands.
- It is 100% READ-ONLY and will not modify local or remote server states.
- Results are saved strictly to a local CSV file.
"""

import paramiko
import csv
import argparse
import sys
import time
from getpass import getpass

RULES = {
    '.env': {
        'type': 'file',
        'safe_perms': ['600', '644', '400', '444'],
        'critical_perms': ['777', '666', '775', '755']
    },
    'storage': {
        'type': 'dir',
        'safe_perms': ['755', '775'],
        'critical_perms': ['777', '666']
    },
    'bootstrap/cache': {
        'type': 'dir',
        'safe_perms': ['755', '775'],
        'critical_perms': ['777', '666']
    },
    'public': {
        'type': 'dir',
        'safe_perms': ['755', '750'],
        'critical_perms': ['777', '666']
    }
}

class CloudPanelAuditor:
    def __init__(self, host, username, password):
        self.host = host
        self.username = username
        self.password = password
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.results = []

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
                self.username = user  # Update active username
                return True
            except paramiko.AuthenticationException:
                print(f"[-] Authentication failed for '{user}'.")
            except Exception as e:
                print(f"[-] Connection error for '{user}' - {e}")
                
        print("[-] Error: All authentication attempts failed. Please check your credentials.")
        return False

    def exec_sudo_command(self, cmd):
        """Execute a command over SSH handling both root and standard users safely."""
        if self.username == 'root':
            # Root executing directly without sudo
            stdin, stdout, stderr = self.client.exec_command(cmd)
            return stdout.read().decode('utf-8').strip(), stderr.read().decode('utf-8').strip()
        else:
            # Standard user executing with sudo -S
            stdin, stdout, stderr = self.client.exec_command(f"sudo -S {cmd}")
            stdin.write(self.password + "\n")
            stdin.flush()
            return stdout.read().decode('utf-8').strip(), stderr.read().decode('utf-8').strip()

    def discover_sites(self):
        """Discover all domains managed by CloudPanel."""
        print("[*] Discovering domains under /home/*/htdocs/* ...")
        cmd = 'find /home -mindepth 3 -maxdepth 3 -type d -path "*/htdocs/*" 2>/dev/null'
        out, err = self.exec_sudo_command(cmd)
        
        if not out:
            print("[-] No domains found.")
            if err and "password" not in err.lower():
                print(f"[-] Sudo/Find Error: {err}")
            return []
            
        sites = out.split('\n')
        # Structure: /home/site-user/htdocs/domain.com
        found_sites = []
        for s in sites:
            try:
                parts = s.split('/')
                if len(parts) >= 5 and parts[1] == 'home' and parts[3] == 'htdocs':
                    site_user = parts[2]
                    domain = parts[4]
                    
                    # Exclude laysos.co.uk
                    if 'laysos.co.uk' in domain or 'lay0co12uk' in site_user:
                        continue
                        
                    found_sites.append((site_user, domain, s))
            except IndexError:
                continue
                
        print(f"[+] Found {len(found_sites)} domains across {len(set([s[0] for s in found_sites]))} users.")
        return found_sites

    def audit_target(self, site_user, base_path, target_relative, rule_def, domain_name):
        """Audit a specific known target (like .env or storage) for a given domain."""
        target_path = f"{base_path}/{target_relative}" if target_relative else base_path
        display_target = f"{domain_name}/{target_relative}" if target_relative else domain_name
        
        cmd = f'su - {site_user} -c "stat -c \\"%a|%U:%G|%F\\" {target_path} 2>/dev/null"'
        if self.username == 'root':
            cmd = f'stat -c "%a|%U:%G|%F" {target_path} 2>/dev/null'
            
        out, err = self.exec_sudo_command(cmd)
        
        if not out:
            return
            
        try:
            perms, owner, ftype = out.split('|')
            if len(perms) > 3:
                perms = perms[-3:]
                
            self.evaluate_permissions(site_user, base_path, display_target, perms, owner, rule_def)
        except ValueError:
            pass

    def evaluate_permissions(self, site_user, base_path, target, perms, owner, rule_def):
        status = "OK"
        explanation = "Permissions look secure."
        expected = "/".join(rule_def['safe_perms'])
        
        if perms in rule_def['critical_perms']:
            status = "CRITICAL"
            explanation = f"Highly insecure permissions detected ({perms}). Over-permissive."
        elif perms not in rule_def['safe_perms']:
            status = "WARNING"
            explanation = f"Permissions ({perms}) are not strictly aligned with secure presets."
            
        # Ownership check
        try:
            owner_user, owner_group = owner.split(':')
            if owner_user != site_user:
                if status == "OK":
                    status = "WARNING"
                explanation += f" Ownership mismatch (owned by {owner_user}, expected {site_user})."
        except ValueError:
            pass
            
        self.results.append({
            'site_name': site_user,
            'path': base_path,
            'target': target,
            'current_permission': perms,
            'owner': owner,
            'expected_permission': expected,
            'status': status,
            'explanation': explanation.strip()
        })

    def sweep_domain(self, site_user, domain_path, domain_name):
        """Deep level recursive sweep of the domain to catch general permission violations."""
        
        # 1. Sweep world-writable files (Equivalent to 777 or 666)
        cmd_files = f'find {domain_path} -type f -perm -002 2>/dev/null | head -n 50'
        out, _ = self.exec_sudo_command(cmd_files)
        if out:
            for f in out.split('\n'):
                f = f.strip()
                if not f: continue
                # Extract specific permission just for clarity via stat
                cmd_stat = f'stat -c "%a" "{f}" 2>/dev/null'
                p_out, _ = self.exec_sudo_command(cmd_stat)
                perm = p_out[-3:] if p_out and len(p_out) >= 3 else 'WW'
                
                self.results.append({
                    'site_name': site_user,
                    'path': domain_path,
                    'target': f.replace(f"{domain_path}/", f"{domain_name}/"),
                    'current_permission': perm,
                    'owner': 'any',
                    'expected_permission': '644',
                    'status': 'CRITICAL',
                    'explanation': 'File is world-writable. Extremely severe security risk.'
                })
                
        # 2. Sweep world-writable directories
        cmd_dirs = f'find {domain_path} -type d -perm -002 2>/dev/null | head -n 50'
        out, _ = self.exec_sudo_command(cmd_dirs)
        if out:
            for d in out.split('\n'):
                d = d.strip()
                if not d: continue
                cmd_stat = f'stat -c "%a" "{d}" 2>/dev/null'
                p_out, _ = self.exec_sudo_command(cmd_stat)
                perm = p_out[-3:] if p_out and len(p_out) >= 3 else 'WW'
                
                self.results.append({
                    'site_name': site_user,
                    'path': domain_path,
                    'target': d.replace(f"{domain_path}/", f"{domain_name}/"),
                    'current_permission': perm,
                    'owner': 'any',
                    'expected_permission': '755',
                    'status': 'CRITICAL',
                    'explanation': 'Directory is world-writable. Anyone can hijack/upload files.'
                })
                
        # 3. Sweep ownership misconfigurations (finding files not owned by site user)
        cmd_owner = f'find {domain_path} ! -user {site_user} 2>/dev/null | head -n 50'
        out, _ = self.exec_sudo_command(cmd_owner)
        if out:
            for p in out.split('\n'):
                p = p.strip()
                if not p: continue
                self.results.append({
                    'site_name': site_user,
                    'path': domain_path,
                    'target': p.replace(f"{domain_path}/", f"{domain_name}/"),
                    'current_permission': 'N/A',
                    'owner': 'Incorrect',
                    'expected_permission': site_user,
                    'status': 'WARNING',
                    'explanation': f'File/dir not properly owned by designated user ({site_user}).'
                })

    def run_audit(self):
        sites = self.discover_sites()
        for site_user, domain, domain_path in sites:
            print(f"[*] Auditing domain: {domain} ({site_user})...")
            
            # 1. Audit root folder safely
            self.audit_target(site_user, domain_path, '', {
                'safe_perms': ['755', '750'],
                'critical_perms': ['777', '775', '666']
            }, domain)
            
            # 2. Audit standard nested framework paths (Laravel checks)
            for target, rule in RULES.items():
                self.audit_target(site_user, domain_path, target, rule, domain)
                
            # 3. Sweep general files recursively
            self.sweep_domain(site_user, domain_path, domain)
                
    def export_csv(self, filename="cloudpanel_audit_report.csv"):
        if not self.results:
            print("[-] No audit results to export.")
            return

        keys = ['site_name', 'path', 'target', 'current_permission', 'owner', 'expected_permission', 'status', 'explanation']
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=keys)
                writer.writeheader()
                writer.writerows(self.results)
            print(f"[+] Local report successfully generated: {filename}")
        except Exception as e:
            print(f"[-] Failed to write CSV file: {e}")

    def close(self):
        if self.client:
            self.client.close()

def main():
    parser = argparse.ArgumentParser(description="CloudPanel Read-Only Permission Auditor")
    parser.add_argument("-H", "--host", required=True, help="IP Address or hostname of the CloudPanel server")
    parser.add_argument("-u", "--user", default="root", help="SSH Username (default: root)")
    parser.add_argument("-p", "--password", help="SSH Password (optional, will prompt securely if not provided)")
    
    args = parser.parse_args()
    
    # Securely prompt for password if not passed as argument
    password = args.password
    if not password:
        try:
            password = getpass(f"Password for {args.user}@{args.host} (used for both root/laysos): ")
        except KeyboardInterrupt:
            print("\nProcess interrupted by user.")
            sys.exit(0)
        
    auditor = CloudPanelAuditor(args.host, args.user, password)
    
    start_time = time.time()
    if auditor.connect():
        auditor.run_audit()
        auditor.export_csv("cloudpanel_audit_report.csv")
        auditor.close()
        elapsed = time.time() - start_time
        print(f"[*] Audit completed safely in {elapsed:.2f} seconds.")
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
