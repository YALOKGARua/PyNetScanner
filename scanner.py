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

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class NetworkScanner:
    def __init__(self):
        self.active_hosts = []
        self.scan_history = []
        self.lock = threading.Lock()

    def get_network_info(self) -> Tuple[str, str]:
        try:
            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET][1]
            interfaces = netifaces.interfaces()
            logging.info(f"Используемый интерфейс: {default_gateway}")
            
            for iface in interfaces:
                if iface == default_gateway:
                    addrs = netifaces.ifaddresses(iface)
                    ip_info = addrs[netifaces.AF_INET][0]
                    ip = ip_info['addr']
                    netmask = ip_info['netmask']
                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    logging.info(f"Сеть: {network.network_address}/{network.netmask}")
                    return str(network.network_address), str(network.netmask)
        except Exception as e:
            logging.error(f"Ошибка определения сети: {e}")
            return "", ""

    def scan_network_arp(self, network: str, netmask: str) -> List[Tuple[str, str]]:
        with self.lock:
            self.active_hosts = []
            try:
                if not scapy.get_working_ifaces():
                    logging.error("Нет доступного провайдера pcap (проверьте Npcap)")
                    return []
                network_cidr = f"{network}/{ipaddress.IPv4Network(f'{network}/{netmask}').prefixlen}"
                logging.info(f"Сканирование ARP: {network_cidr}")
                
                arp_request = scapy.ARP(pdst=network_cidr)
                broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                arp_request_broadcast = broadcast / arp_request
                
                answered_list = scapy.srp(arp_request_broadcast, timeout=10, verbose=False, retry=3)[0]
                
                for sent, received in answered_list:
                    ip = received.psrc
                    mac = received.hwsrc
                    self.active_hosts.append((ip, mac))
                    logging.info(f"Найден хост ARP: IP={ip}, MAC={mac}")
                
                return self.active_hosts
            except Exception as e:
                logging.error(f"Ошибка ARP-сканирования: {e}")
                return []

    def scan_network_ping(self, network: str, netmask: str) -> List[str]:
        active_ips = []
        try:
            network_obj = ipaddress.IPv4Network(f"{network}/{netmask}", strict=False)
            logging.info(f"Сканирование Ping: {network_obj}")
            
            for ip in network_obj.hosts():
                ip_str = str(ip)
                if self.ping_ip(ip_str):
                    active_ips.append(ip_str)
                    logging.info(f"Найден хост Ping: IP={ip_str}")
                time.sleep(0.1)
            return active_ips
        except Exception as e:
            logging.error(f"Ошибка Ping-сканирования: {e}")
            return []

    def ping_ip(self, ip: str) -> bool:
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '4', ip]
            output = subprocess.run(command, capture_output=True, text=True, timeout=2)
            return output.returncode == 0
        except Exception as e:
            logging.error(f"Ошибка пинга IP {ip}: {e}")
            return False

    def save_results(self, filename: str, hosts: List[Tuple[str, str]]):
        try:
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["IP", "MAC"])
                for ip, mac in hosts:
                    writer.writerow([ip, mac])
            logging.info(f"Результаты сохранены в {filename}")
        except Exception as e:
            logging.error(f"Ошибка сохранения: {e}")

    def load_history(self) -> List[Dict]:
        if os.path.exists('scan_history.json'):
            with open('scan_history.json', 'r') as f:
                return json.load(f)
        return []

    def save_history(self, network: str, netmask: str, hosts: List[Tuple[str, str]]):
        history_entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "network": f"{network}/{ipaddress.IPv4Network(f'{network}/{netmask}').prefixlen}",
            "hosts": [{"ip": ip, "mac": mac} for ip, mac in hosts]
        }
        history = self.load_history()
        history.append(history_entry)
        with open('scan_history.json', 'w') as f:
            json.dump(history, f, indent=4)
        logging.info("История обновлена")

    def generate_test_data(self, count: int) -> List[Tuple[str, str]]:
        test_hosts = []
        for i in range(count):
            ip = f"192.168.88.{random.randint(2, 254)}"
            mac = ':'.join(random.choices(string.hexdigits[:6], k=6))
            test_hosts.append((ip, mac))
        return test_hosts

    def scan_ports(self, ip: str) -> Dict[int, bool]:
        open_ports = {}
        common_ports = [21, 22, 80, 443, 3389, 8080]
        for port in common_ports:
            sock = scapy.socket.socket(scapy.socket.AF_INET, scapy.socket.SOCK_STREAM)
            result = sock.connect_ex((ip, port))
            open_ports[port] = result == 0
            sock.close()
            time.sleep(0.1)
        return open_ports

    def extended_scan(self, network: str, netmask: str) -> Dict:
        results = {"arp_hosts": [], "ping_hosts": [], "port_scans": {}}
        arp_hosts = self.scan_network_arp(network, netmask)
        ping_hosts = self.scan_network_ping(network, netmask)
        
        results["arp_hosts"] = arp_hosts
        results["ping_hosts"] = ping_hosts
        
        for ip, _ in arp_hosts[:5]:
            results["port_scans"][ip] = self.scan_ports(ip)
        
        self.save_history(network, netmask, arp_hosts)
        self.save_results("scan_results.csv", arp_hosts)
        return results

    def run_extended_scan_thread(self, network: str, netmask: str, callback):
        threading.Thread(target=lambda: callback(self.extended_scan(network, netmask)), daemon=True).start()

    def generate_dummy_data(self):
        for i in range(100):
            test_data = self.generate_test_data(10)
            for ip, mac in test_data:
                logging.info(f"Генерация данных {i}: {ip}, {mac}")
                time.sleep(0.01)