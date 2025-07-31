"""
SKO's NETWORK SCANNER
Created by Sam Quarm
Ethical Use Only. For educational and diagnostic purposes.

"""
#Imports
from scapy.all import ARP, Ether, srp
import socket
import requests
import netifaces
from datetime import datetime
from ipaddress import ip_interface
import nmap
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from collections import Counter
from threading import Lock




# [!] File Path details[!] <--------------------- CHANGE THE FILE PATH TO SAVE THE ENTIRE SCAN TO A CREATED LOG!!!!!!!!!!!!

# === Config === #
DEFAULT_SUBNET = "192.168.1.0/24"
DEFAULT_PORTS = [21, 22, 23, 25, 80, 135, 139, 443, 445, 3389]
LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "scan_log.txt"
LOG_DIR.mkdir(parents=True, exist_ok=True)
PORT_PROTOCOLS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
}

def get_network_info():
    """Get local IP, gateway, subnet, and public IP."""
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        default_gateway = netifaces.gateways()['default'][netifaces.AF_INET][0]
        iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
        ip_info = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
        subnet = f"{ip_info['addr']}/{ip_info['netmask']}"
        public_ip = requests.get('https://api.ipify.org').text

        return {
            'local_ip': local_ip,
            'gateway': default_gateway,
            'subnet': subnet,
            'public_ip': public_ip
        }
    except Exception as e:
        print(f"[!] Failed to get network info: {e}")
        return {}

def scan_arp(subnet):
    """Send ARP requests and return discovered hosts."""
    arp = ARP(pdst=subnet)
    ether = Ether(dst='ff:ff:ff:ff:ff:ff')
    packet = ether / arp
    result = srp(packet, timeout=2, verbose=0)[0]

    hosts = {}
    for _, received in result:
        print(f"[+] Host found: {received.psrc} - MAC: {received.hwsrc}")
        hosts[received.psrc] = received.hwsrc
    return hosts

def os_scan(target_ip):
    """Perform an OS scan using nmap."""
    scanner = nmap.PortScanner()
    output = f"\n--- OS Scan for {target_ip} ---\n"

    try:
        scanner.scan(hosts=target_ip, arguments='-O -Pn -T4 -p ' + ','.join(map(str, DEFAULT_PORTS)))
        if target_ip in scanner.all_hosts():
            os_matches = scanner[target_ip].get('osmatch', [])
            if os_matches:
                output += "OS Matches:\n"
                for match in os_matches:
                    output += f"  - {match['name']} (Accuracy: {match['accuracy']}%)\n"
            else:
                output += "[!] OS detection failed.\n"
        else:
            output += "[!] Host is down or not responding.\n"
    except Exception as e:
        output += f"[!] OS scan error: {e}\n"

    return output

def port_scan(ip, net_info, ports=DEFAULT_PORTS):
    """Perform TCP port scan."""
    output = f'\nPort Scan for {ip}:\n'
    output += f"- Gateway: {net_info.get('gateway', 'N/A')}\n"
    output += f"- Subnet: {net_info.get('subnet', 'N/A')}\n"
    output += f"- Public IP: {net_info.get('public_ip', 'N/A')}\n"

    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((ip, port))
                status = "OPEN" if result == 0 else "CLOSED/FILTERED"
                protocol = PORT_PROTOCOLS.get(port, 'Unknown')
                output += f"  Port {port}({protocol}): {status}\n"
        except Exception as e:
            output += f"  Port {port} error: {e}\n"
    return output

def full_host_scan(host, mac_addr, net_info):
    """Scan a host fully and log results."""
    log = f"\n==== Host: {host} | MAC: {mac_addr} ====\n"
    log += os_scan(host)
    log += port_scan(host, net_info)
    log += f"==== End of {host} ====\n"

    with open(LOG_FILE, 'a') as f:
        f.write(log)

def main():
    parser = argparse.ArgumentParser(description="SKO's Network Scanner")
    parser.add_argument('-s', '--subnet', default=DEFAULT_SUBNET, help='Subnet to scan (default: 192.168.1.0/24)')
    args = parser.parse_args()

    net_info = get_network_info()

    with open(LOG_FILE, 'a') as f:
        f.write(f'\n\n=== Scan Started: {datetime.now()} ===\n')

    print("[*] Starting ARP Scan...")
    hosts = scan_arp(args.subnet)

    print("[*] Starting full scan on discovered hosts...")
    with ThreadPoolExecutor(max_workers=10) as executor:
        for host, mac in hosts.items():
            executor.submit(full_host_scan, host, mac, net_info)
            # === Summary === #
    summary = f"""
    ========= SCAN SUMMARY =========
    Total Hosts Found: {len(hosts)}
    Subnet Scanned: {args.subnet}
    Local IP: {net_info.get('local_ip', 'N/A')}
    Public IP: {net_info.get('public_ip', 'N/A')}
    ================================
    """

    with open(LOG_FILE, 'a') as f:
        f.write(f'=== Scan Completed: {datetime.now()} ===\n')

    
    print(summary)
    with open(LOG_FILE, 'a') as f:
        f.write(summary)

    print(f"[*] Logs saved to: {LOG_FILE.resolve()}")

if __name__ == '__main__':
    main()
