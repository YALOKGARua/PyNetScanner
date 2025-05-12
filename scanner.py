import scapy.all as scapy
import netifaces
import ipaddress
import subprocess
import platform
import logging
import threading
import time
import json
import csv
from typing import List, Tuple, Dict, Optional
import os
import random
import string
import nmap
import psutil
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class NetworkScanner:
    def __init__(self):
        self.active_hosts = []
        self.scan_history = []
        self.lock = threading.Lock()
        self.nm = nmap.PortScanner()
        self.common_ports = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443]

    def get_network_info(self) -> Tuple[str, str]:
        try:
            interfaces = psutil.net_if_addrs()
            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET][0]
            default_interface = gateways['default'][netifaces.AF_INET][1]
            
            for iface, addrs in interfaces.items():
                if iface == default_interface:
                    for addr in addrs:
                        if addr.family == psutil.AF_INET:
                            ip = addr.address
                            netmask = addr.netmask
                            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                            logging.info(f"Network: {network.network_address}/{network.netmask} (Gateway: {default_gateway})")
                            return str(network.network_address), str(network.netmask)
            return "", ""
        except Exception as e:
            logging.error(f"Network detection error: {e}")
            return "", ""

    def scan_network_arp(self, network: str, netmask: str) -> List[Tuple[str, str, str]]:
        with self.lock:
            self.active_hosts = []
            try:
                if not scapy.get_working_ifaces():
                    logging.error("No pcap provider available (check Npcap installation)")
                    return []
                    
                network_cidr = f"{network}/{ipaddress.IPv4Network(f'{network}/{netmask}').prefixlen}"
                logging.info(f"Starting ARP scan: {network_cidr}")
                
                arp_request = scapy.ARP(pdst=network_cidr)
                broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                arp_request_broadcast = broadcast / arp_request
                
                answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False, retry=2)[0]
                
                for sent, received in answered_list:
                    ip = received.psrc
                    mac = received.hwsrc
                    vendor = self.get_mac_vendor(mac)
                    self.active_hosts.append((ip, mac, vendor))
                    logging.info(f"Found host: IP={ip}, MAC={mac}, Vendor={vendor}")
                
                return self.active_hosts
            except Exception as e:
                logging.error(f"ARP scan error: {e}")
                return []

    def get_mac_vendor(self, mac: str) -> str:
        try:
            mac_prefix = mac.replace(":", "")[:6].upper()
            with open("mac_vendors.txt", "r") as f:
                for line in f:
                    if line.startswith(mac_prefix):
                        return line.split("\t")[1].strip()
            return "Unknown"
        except:
            return "Unknown"

    def scan_network_ping(self, network: str, netmask: str) -> List[str]:
        active_ips = []
        try:
            network_obj = ipaddress.IPv4Network(f"{network}/{netmask}", strict=False)
            logging.info(f"Starting Ping scan: {network_obj}")
            
            threads = []
            max_threads = 50
            
            def ping_host(ip):
                if self.ping_ip(str(ip)):
                    with self.lock:
                        active_ips.append(str(ip))
                        logging.info(f"Found host (Ping): {ip}")
            
            for ip in network_obj.hosts():
                while threading.active_count() > max_threads:
                    time.sleep(0.1)
                thread = threading.Thread(target=ping_host, args=(ip,), daemon=True)
                threads.append(thread)
                thread.start()
            
            for thread in threads:
                thread.join()
                
            return sorted(active_ips, key=lambda ip: [int(x) for x in ip.split(".")])
        except Exception as e:
            logging.error(f"Ping scan error: {e}")
            return []

    def ping_ip(self, ip: str) -> bool:
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '1', '-w', '1000', ip]
            result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return result.returncode == 0
        except:
            return False

    def scan_ports(self, ip: str) -> Dict[int, Dict[str, str]]:
        try:
            logging.info(f"Starting port scan for {ip}")
            results = {}
            self.nm.scan(ip, arguments=f'-p{",".join(map(str, self.common_ports))} -sV -T4')
            
            if ip in self.nm.all_hosts():
                for port in self.nm[ip].all_tcp():
                    port_info = self.nm[ip]['tcp'][port]
                    results[port] = {
                        'state': port_info['state'],
                        'service': port_info['name'],
                        'version': port_info['version']
                    }
            return results
        except Exception as e:
            logging.error(f"Port scan error for {ip}: {e}")
            return {}

    def extended_scan(self, network: str, netmask: str) -> Dict:
        results = {
            "timestamp": datetime.now().isoformat(),
            "network": f"{network}/{ipaddress.IPv4Network(f'{network}/{netmask}').prefixlen}",
            "arp_hosts": [],
            "ping_hosts": [],
            "port_scans": {}
        }
        
        arp_hosts = self.scan_network_arp(network, netmask)
        ping_hosts = self.scan_network_ping(network, netmask)
        
        results["arp_hosts"] = arp_hosts
        results["ping_hosts"] = ping_hosts
        
        for ip, mac, vendor in arp_hosts[:5]:
            results["port_scans"][ip] = self.scan_ports(ip)
        
        self.save_history(network, netmask, arp_hosts)
        self.save_results("scan_results.csv", arp_hosts)
        return results

    def save_results(self, filename: str, hosts: List[Tuple[str, str, str]]):
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["IP", "MAC", "Vendor", "Timestamp"])
                for ip, mac, vendor in hosts:
                    writer.writerow([ip, mac, vendor, datetime.now().isoformat()])
            logging.info(f"Results saved to {filename}")
        except Exception as e:
            logging.error(f"Error saving results: {e}")

    def load_history(self) -> List[Dict]:
        try:
            if os.path.exists('scan_history.json'):
                with open('scan_history.json', 'r', encoding='utf-8') as f:
                    return json.load(f)
            return []
        except Exception as e:
            logging.error(f"Error loading history: {e}")
            return []

    def save_history(self, network: str, netmask: str, hosts: List[Tuple[str, str, str]]):
        try:
            history_entry = {
                "timestamp": datetime.now().isoformat(),
                "network": f"{network}/{ipaddress.IPv4Network(f'{network}/{netmask}').prefixlen}",
                "hosts": [{"ip": ip, "mac": mac, "vendor": vendor} for ip, mac, vendor in hosts]
            }
            history = self.load_history()
            history.append(history_entry)
            with open('scan_history.json', 'w', encoding='utf-8') as f:
                json.dump(history, f, indent=4, ensure_ascii=False)
            logging.info("History updated")
        except Exception as e:
            logging.error(f"Error saving history: {e}")

    def run_extended_scan_thread(self, network: str, netmask: str, callback):
        threading.Thread(target=lambda: callback(self.extended_scan(network, netmask)), daemon=True).start()

    def generate_test_data(self, count: int) -> List[Tuple[str, str]]:
        test_hosts = []
        for i in range(count):
            ip = f"192.168.88.{random.randint(2, 254)}"
            mac = ':'.join(random.choices(string.hexdigits[:6], k=6))
            test_hosts.append((ip, mac))
        return test_hosts

    def generate_dummy_data(self):
        for i in range(100):
            test_data = self.generate_test_data(10)
            for ip, mac in test_data:
                logging.info(f"Генерация данных {i}: {ip}, {mac}")
                time.sleep(0.01)