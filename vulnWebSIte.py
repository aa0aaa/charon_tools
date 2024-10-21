import requests
from bs4 import BeautifulSoup
import nmap
import subprocess
import os
import time
import sys

# Function to print the tool banner with the name ARTeam and rights by Charon
def banner():
    print("""
                          (                             
                   (      )\ )  *   )                   
                   )\    (()/(` )  /(   (     )     )   
                ((((_)(   /(_))( )(_)) ))\ ( /(    (    
                 )\ _ )\ (_)) (_(_()) /((_))(_))   )\  '
                 (_)_\(_)| _ \|_   _|(_)) ((_)_  _((_)) 
                  / _ \  |   /  | |  / -_)/ _` || '  \()
                 /_/ \_\ |_|_\  |_|  \___|\__,_||_|_|_| 
    ---------------------------------------------------------------
                     Created by: ARTeam - All Rights to Charon
    ---------------------------------------------------------------
    """)

# Progress bar for visualizing process completion
def progress_bar(duration):
    toolbar_width = 40
    sys.stdout.write("[%s]" % (" " * toolbar_width))
    sys.stdout.flush()
    sys.stdout.write("\b" * (toolbar_width + 1))  # return to start of line, after '['
    
    for i in range(toolbar_width):
        time.sleep(duration / toolbar_width)
        sys.stdout.write("-")
        sys.stdout.flush()
    
    sys.stdout.write("]\n")

# 1. Basic info gathering using requests and BeautifulSoup
def gather_info(url):
    try:
        print("\n[+] Gathering website information...\n")
        progress_bar(2)
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        title = soup.find('title').text if soup.find('title') else "No Title"
        server = response.headers.get('Server', 'Unknown Server')
        print(f"[+] Title: {title}")
        print(f"[+] Status Code: {response.status_code}")
        print(f"[+] Server: {server}")
        return response
    except Exception as e:
        print(f"[-] Error gathering info: {str(e)}")

# 2. Running Nikto for web vulnerability scanning
def run_nikto(target):
    try:
        print("\n[+] Running Nikto vulnerability scan...\n")
        progress_bar(3)
        subprocess.run(['nikto', '-h', target], check=True)
    except Exception as e:
        print(f"[-] Nikto scan failed: {str(e)}")

# 3. Running SQLMap to check for SQL Injection
def run_sqlmap(url):
    try:
        print("\n[+] Running SQLMap for SQL injection vulnerabilities...\n")
        progress_bar(3)
        subprocess.run(['sqlmap', '-u', url, '--batch', '--crawl=2'], check=True)
    except Exception as e:
        print(f"[-] SQLMap scan failed: {str(e)}")

# 4. XSS Vulnerability check
def check_xss(url):
    print("\n[+] Checking for XSS vulnerabilities...\n")
    progress_bar(2)
    payload = "<script>alert('XSS')</script>"
    try:
        response = requests.post(url, data={'input': payload})
        if payload in response.text:
            print(f"[+] XSS vulnerability detected at {url}")
        else:
            print(f"[-] No XSS vulnerability detected at {url}")
    except Exception as e:
        print(f"[-] Error during XSS test: {str(e)}")

# 5. Nmap port scanning (Moved to the end of the process)
def nmap_scan(target):
    try:
        print("\n[+] Scanning open ports using Nmap...\n")
        progress_bar(4)
        nm = nmap.PortScanner()
        nm.scan(target, '1-65535')  # Expanded to scan all ports
        for host in nm.all_hosts():
            print(f"Host : {host} ({nm[host].hostname()})")
            print(f"State : {nm[host].state()}")
            for proto in nm[host].all_protocols():
                print(f"Protocol : {proto}")
                lport = nm[host][proto].keys()
                for port in lport:
                    print(f"Port : {port}\tState : {nm[host][proto][port]['state']}")
    except Exception as e:
        print(f"[-] Nmap scan failed: {str(e)}")

# 6. Saving output to file
def save_report(report, filename="scan_report.txt"):
    try:
        with open(filename, "w") as file:
            file.write(report)
        print(f"[+] Report saved as {filename}")
    except Exception as e:
        print(f"[-] Error saving report: {str(e)}")

# Main function to control the workflow
def main():
    banner()
    url = input("[*] Enter the target URL (e.g., http://example.com): ")
    domain = url.split('//')[-1]  # Get domain from URL
    
    report = ""

    # Step 1: Gather info
    report += "[+] Gathering website information...\n"
    gather_info(url)
    
    # Step 2: Run Nikto for web server vulnerabilities
    report += "[+] Running Nikto vulnerability scan...\n"
    run_nikto(url)
    
    # Step 3: Run SQLMap for SQL Injection vulnerabilities
    report += "[+] Running SQLMap for SQL injection vulnerabilities...\n"
    run_sqlmap(url)
    
    # Step 4: XSS vulnerability check
    report += "[+] Checking for XSS vulnerabilities...\n"
    check_xss(url)
    
    # Step 5: Nmap scan (Final Step)
    report += "[+] Running Nmap port scan...\n"
    nmap_scan(domain)

    # Step 6: Save report
    save_report(report)

    print("\n-----------------------------------------------------")
    print("Scan complete. Report saved as 'scan_report.txt'.")
    print("Created by: ARTeam - Rights by Charon")
    print("-----------------------------------------------------")

if __name__ == "__main__":
    main()
