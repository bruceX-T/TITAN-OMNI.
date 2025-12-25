#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Project: TITAN XIII - OMNI
Description: Automated Full-Stack Security Assessment Tool
Author: BruceX Security Ops
License: MIT
"""

import sys
import os
import socket
import ssl
import requests
import concurrent.futures
import time
from datetime import datetime

# Global Configuration
TIMEOUT = 3
MAX_WORKERS = 20
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"

# ANSI Colors
C_CYAN   = '\033[96m'
C_GREEN  = '\033[92m'
C_RED    = '\033[91m'
C_YELLOW = '\033[93m'
C_RESET  = '\033[0m'
BOLD     = '\033[1m'

# Target Definitions
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 5432, 8080, 8443]
SENSITIVE_PATHS = [
    "robots.txt", ".env", "config.php", ".git/HEAD", "wp-login.php", 
    "backup.sql", "error_log", "phpinfo.php", "id_rsa", ".ds_store"
]

def print_banner():
    os.system('clear')
    print(f"""{C_CYAN}
    ████████ ██ ████████  █████  ███    ██ 
       ██    ██    ██    ██   ██ ████   ██ 
       ██    ██    ██    ███████ ██ ██  ██ 
       ██    ██    ██    ██   ██ ██  ██ ██ 
       ██    ██    ██    ██   ██ ██   ████ v13
    
    [ OMNI SECURITY SUITE | BRUCEX OPS ]
    {C_RESET}""")

def check_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.5)
            if s.connect_ex((ip, port)) == 0:
                return port
    except:
        pass
    return None

def scan_ports(domain):
    print(f"{BOLD}[*] Resolving target and mapping network surface...{C_RESET}")
    try:
        target_ip = socket.gethostbyname(domain)
        print(f"    > Target IP: {target_ip}")
        
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_port = {executor.submit(check_port, target_ip, port): port for port in COMMON_PORTS}
            for future in concurrent.futures.as_completed(future_to_port):
                port = future.result()
                if port:
                    print(f"    > {C_GREEN}Open Port: {port}{C_RESET}")
                    open_ports.append(port)
        return open_ports
    except socket.gaierror:
        print(f"{C_RED}[!] DNS Resolution failed.{C_RESET}")
        return []

def scan_http_headers(url):
    print(f"\n{BOLD}[*] Analyzing HTTP Security Headers...{C_RESET}")
    vulns = []
    try:
        r = requests.get(url, headers={'User-Agent': USER_AGENT}, timeout=TIMEOUT, verify=False)
        headers = r.headers
        
        checks = {
            "X-Frame-Options": "Clickjacking protection missing",
            "Content-Security-Policy": "XSS mitigation missing",
            "Strict-Transport-Security": "HSTS missing",
            "X-Content-Type-Options": "MIME sniffing protection missing"
        }

        for header, msg in checks.items():
            if header not in headers:
                print(f"    {C_YELLOW}[!] Missing: {header}{C_RESET}")
                vulns.append(f"{header} - {msg}")
            else:
                print(f"    {C_GREEN}[OK] {header}{C_RESET}")
    except requests.exceptions.RequestException as e:
        print(f"{C_RED}[!] HTTP Connection failed: {str(e)[:50]}...{C_RESET}")
    
    return vulns

def scan_sensitive_files(url):
    print(f"\n{BOLD}[*] Enumerating sensitive endpoints...{C_RESET}")
    found = []
    for path in SENSITIVE_PATHS:
        target = f"{url}/{path}"
        try:
            r = requests.head(target, headers={'User-Agent': USER_AGENT}, timeout=2, verify=False)
            if r.status_code == 200:
                print(f"    {C_RED}[ALERT] Accessible: /{path}{C_RESET}")
                found.append(path)
        except:
            pass
    return found

def check_ssl(domain):
    print(f"\n{BOLD}[*] Verifying SSL/TLS Configuration...{C_RESET}")
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])
                print(f"    {C_GREEN}[OK] Valid Certificate. Issuer: {issuer.get('organizationName', 'Unknown')}{C_RESET}")
                return True
    except:
        print(f"    {C_RED}[FAIL] SSL Handshake failed or invalid certificate.{C_RESET}")
        return False

def generate_report(domain, ports, header_vulns, files_found, ssl_status):
    filename = f"report_{domain}_{int(time.time())}.txt"
    with open(filename, "w") as f:
        f.write(f"TITAN OMNI - SECURITY AUDIT REPORT\n")
        f.write(f"target: {domain}\n")
        f.write(f"timestamp: {datetime.now()}\n")
        f.write("-" * 40 + "\n\n")
        
        f.write("[NETWORK]\n")
        f.write(f"Open Ports: {ports if ports else 'None detected'}\n\n")
        
        f.write("[WEB SECURITY]\n")
        if header_vulns:
            f.write("Missing Headers:\n")
            for v in header_vulns: f.write(f" - {v}\n")
        else:
            f.write("Headers: Secure\n")
            
        if files_found:
            f.write("\nExposed Files:\n")
            for file in files_found: f.write(f" - /{file}\n")
            
        f.write(f"\n[SSL]\nStatus: {'Secure' if ssl_status else 'Insecure/None'}\n")
        f.write("\n" + "-" * 40 + "\nGenerated by TITAN XIII")
    
    return filename

def main():
    requests.packages.urllib3.disable_warnings()
    print_banner()
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        try:
            target = input(f"{BOLD}Target IP/Domain > {C_RESET}").strip()
        except KeyboardInterrupt:
            sys.exit()

    if not target: sys.exit(1)
    
    # URL Parsing
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    url = f"https://{domain}"
    
    # Execution
    start_time = time.time()
    
    ports = scan_ports(domain)
    header_issues = scan_http_headers(url)
    files = scan_sensitive_files(url)
    ssl_ok = check_ssl(domain)
    
    report = generate_report(domain, ports, header_issues, files, ssl_ok)
    
    duration = time.time() - start_time
    print(f"\n{BOLD}[+] Audit completed in {duration:.2f}s{C_RESET}")
    print(f"{C_GREEN}[+] Report saved: {report}{C_RESET}")
    
    # Auto-move to downloads if on Android/Termux
    if os.path.exists("/sdcard/Download"):
        os.system(f"cp {report} /sdcard/Download/")
        print(f"{C_CYAN}[+] Copy available in Downloads folder{C_RESET}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Aborted by user.")
        sys.exit()

