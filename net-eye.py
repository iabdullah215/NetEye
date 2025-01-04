import socket
import nmap
import requests
import json
import subprocess
import sys
from termcolor import colored

def discover_live_hosts(subnet):
    print("[INFO] Discovering live hosts...")
    live_hosts = []
    for i in range(1, 255):
        ip = f"{subnet}.{i}"
        result = subprocess.run(["ping", "-c", "1", "-w", "1", ip], stdout=subprocess.DEVNULL)
        if result.returncode == 0:
            live_hosts.append(ip)
    return live_hosts

def resolve_dns(target):
    print("[INFO] Resolving DNS...")
    try:
        ip = socket.gethostbyname(target)
        hostname = socket.gethostbyaddr(ip)[0]
        return {"ip": ip, "hostname": hostname}
    except socket.error as e:
        print(colored(f"[ERROR] DNS resolution failed: {e}", "red"))
        return {"ip": None, "hostname": None}

def grab_banner(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode().strip()
        sock.close()
        return banner
    except Exception:
        return None

def geoip_lookup(ip):
    print("[INFO] Performing GeoIP lookup...")
    url = f"https://geolocation-db.com/json/{ip}&position=true"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
        return {}
    except Exception as e:
        print(colored(f"[ERROR] GeoIP lookup failed: {e}", "red"))
        return {}

def scan_open_ports(target, ports):
    print("[INFO] Scanning open ports...")
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((target, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def detailed_nmap_scan(target):
    print("[INFO] Performing detailed Nmap scan...")
    scanner = nmap.PortScanner()
    try:
        scanner.scan(hosts=target, arguments='-sV -O')
        results = []
        for host in scanner.all_hosts():
            host_info = {
                "host": host,
                "state": scanner[host].state(),
                "protocols": {}
            }
            for proto in scanner[host].all_protocols():
                host_info["protocols"][proto] = {}
                for port in scanner[host][proto].keys():
                    port_info = scanner[host][proto][port]
                    host_info["protocols"][proto][port] = {
                        "name": port_info.get("name", "unknown"),
                        "version": port_info.get("version", "unknown")
                    }
            results.append(host_info)
        return results
    except Exception as e:
        print(colored(f"[ERROR] Nmap scan failed: {e}", "red"))
        return []

def check_vulnerabilities(service, version):
    print(f"[INFO] Checking vulnerabilities for {service} {version}...")
    url = f"https://vulners.com/api/v3/search/lucene/"
    headers = {"User-Agent": "Python Script"}
    query = f"{service} {version}"
    payload = {"query": query, "size": 5}
    try:
        response = requests.post(url, json=payload, headers=headers)
        if response.status_code == 200:
            vulnerabilities = response.json().get("data", {}).get("search", {}).get("documents", [])
            return [vuln["title"] for vuln in vulnerabilities]
        return []
    except Exception as e:
        print(colored(f"[ERROR] Vulnerability check failed: {e}", "red"))
        return []

def main():
    # ASCII Art Display at the Start
    print("""
          
          

 /$$   /$$             /$$|          /$$$$$$$$|
| $$$ | $$            | $$          | $$_____/
| $$$$| $$  /$$$$$$  /$$$$$$        | $$       /$$   /$$  /$$$$$$
| $$ $$ $$ /$$__  $$|_  $$_/        | $$$$$   | $$  | $$ /$$__  $$
| $$  $$$$| $$$$$$$$  | $$          | $$__/   | $$  | $$| $$$$$$$$
| $$\  $$$| $$_____/  | $$ /$$      | $$      | $$  | $$| $$_____/
| $$ \  $$|  $$$$$$$  |  $$$$/      | $$$$$$$$|  $$$$$$$|  $$$$$$$
|__/  \__/ \_______/   \___/        |________/ \____  $$ \_______/
                                               /$$  | $$
                                              |  $$$$$$/
                                               \______/

          

⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⢶⢲⢲⣿⢻⢻⡟⢻⡿⣷⣶⣶⣒⠒⠲⠤⠤⢤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣼⣯⣿⣷⣾⣼⣼⣼⣿⣿⣿⣷⣿⣿⣿⣿⣿⣿⣿⣿⣶⣶⣦⣀⣉⠙⠲⠦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣤⣴⣿⣧⢸⣿⣿⣷⠿⠛⠋⠉⠀⠀⢀⡿⠀⠀⠀⠀⠙⢦⡈⠉⠉⠛⠛⠻⢿⣿⣿⣖⣿⣬⡉⠓⢦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢀⣀⣆⣾⣿⣿⣿⣿⠟⠋⠁⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⢀⣼⣷⣶⣦⣄⠀⠀⠀⠀⠉⣟⠻⢿⣿⣧⡀⠈⠙⠒⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣾⣿⣷⣿⡿⠟⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠲⠤⢤⣤⣿⣿⣿⣿⣿⣿⣷⣀⠀⠀⠀⣿⠀⠀⠈⠻⣿⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢀⣿⣿⡍⠙⢷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢷⠀⠀⠀⠀⠘⢿⣿⣿⣿⣿⡿⠉⢳⠀⢰⡏⠀⠀⠀⠀⠈⢻⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠈⢿⣿⣿⣦⠀⠈⢳⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢧⡀⠀⠀⠀⠀⠈⠉⠉⠳⣄⣀⣼⣷⡟⠀⠀⠀⠀⠀⠀⠀⢻⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣀⠈⠹⢿⣿⣳⣦⡀⠈⠙⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠳⢤⣀⠀⠀⠀⠀⠀⠀⢀⣩⡴⠋⠀⠀⠀⠀⠀⠀⠀⠀⢸⠻⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠻⣦⡀⠀⠹⣿⣷⣿⣷⣤⡈⠙⠳⠶⣄⣀⣀⡀⠀⠀⠀⠀⠀⠀⠉⠙⠛⠶⠶⠶⠛⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡿⠀⠙⣧⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠘⠿⣦⣀⠀⠁⠻⢣⣿⣿⣷⣦⣜⢿⣶⡀⠙⠲⠶⠶⠶⣤⡀⠀⣠⣠⡀⠀⢀⣤⡴⢦⣤⣀⣠⣤⣀⠀⠀⠀⢀⡾⡃⠠⡀⠘⣦⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠈⠙⠷⣤⣄⠀⠙⠺⠿⢿⣿⣷⠀⠀⠀⠀⣀⡀⠀⠀⠉⠙⣁⣉⡉⠛⠋⢁⣀⠘⢳⢉⣀⣀⣙⠳⢦⣤⣛⠀⠛⠶⣝⠀⠘⣦⡀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⠙⠃⠀⠀⠀⠀⢀⡟⠀⢀⣴⠛⠉⠙⠛⠿⢿⡇⣺⡟⠛⠳⠤⠾⠛⠛⠛⠛⠁⠈⠉⠛⠿⠋⠉⠛⠛⠓⠾⠶⠦⣌⣳⡀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡾⠁⠀⣸⠁⠀⠀⠀⠀⠀⣾⢰⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠇⠀⠀⢿⠀⠀⠀⠀⠀⢸⡏⢹⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡄⠀⠀⢨⡇⠀⠀⠀⠀⠀⣧⢸⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣀⣠⡾⠁⠀⠀⠀⠀⢠⡟⣼⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⢱⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡿⣾⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀

                                  BY: !abdu11ah

    """)

    target = input("Enter target IP, hostname, or subnet (e.g., 192.168.1): ").strip()
    report = {"target": target, "results": {}}

    try:
        subnet = target.rsplit('.', 1)[0]
        live_hosts = discover_live_hosts(subnet)
        report["results"]["live_hosts"] = live_hosts

        dns_info = resolve_dns(target)
        report["results"]["dns_info"] = dns_info

        ports = range(1, 1025)
        open_ports = scan_open_ports(target, ports)
        banners = [{"port": port, "banner": grab_banner(target, port)} for port in open_ports]
        report["results"]["open_ports"] = banners

        geoip_data = geoip_lookup(target)
        report["results"]["geoip"] = geoip_data

        nmap_results = detailed_nmap_scan(target)
        report["results"]["nmap"] = nmap_results

        vulnerabilities = []
        for banner_info in banners:
            service = banner_info.get("banner", "unknown")
            if service and " " in service:
                name, version = service.split(" ", 1)
                vulns = check_vulnerabilities(name, version)
                vulnerabilities.extend(vulns)
        report["results"]["vulnerabilities"] = vulnerabilities

    except Exception as e:
        print(colored(f"[ERROR] An unexpected error occurred: {e}", "red"))

    with open(f"scan_report_{target.replace('.', '_')}.json", "w") as file:
        json.dump(report, file, indent=4)
    print("[INFO] Scan completed. Report saved.")

if __name__ == "__main__":
    main()
