import scapy.all as scapy
import netifaces
import ipaddress
import subprocess
import platform
from typing import List, Tuple
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class NetworkScanner:
    def __init__(self):
        self.active_hosts = []
    
    def get_network_info(self) -> Tuple[str, str]:
        try:
            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET][1]
            interfaces = netifaces.interfaces()
            
            for iface in interfaces:
                if iface == default_gateway:
                    addrs = netifaces.ifaddresses(iface)
                    ip_info = addrs[netifaces.AF_INET][0]
                    ip = ip_info['addr']
                    netmask = ip_info['netmask']
                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    return str(network.network_address), str(network.netmask)
        except:
            return "", ""
    
    def scan_network(self, network: str, netmask: str) -> List[Tuple[str, str]]:
        self.active_hosts = []
        try:
            if not scapy.get_working_ifaces():
                logging.error("Нет доступного провайдера pcap (установите Npcap)")
                return []
            network_cidr = f"{network}/{ipaddress.IPv4Network(f'{network}/{netmask}').prefixlen}"
            
            arp_request = scapy.ARP(pdst=network_cidr)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
            for sent, received in answered_list:
                ip = received.psrc
                mac = received.hwsrc
                self.active_hosts.append((ip, mac))
            
            return self.active_hosts
        except:
            return []
    
    def ping_ip(self, ip: str) -> bool:
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '1', ip]
            output = subprocess.run(command, capture_output=True, text=True, timeout=5)
            return output.returncode == 0
        except:
            return False