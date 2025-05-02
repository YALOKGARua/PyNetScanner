import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import webbrowser
from scanner import NetworkScanner
import ipaddress

class NetworkScannerGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("PyNetScanner")
        self.root.geometry("600x400")
        self.scanner = NetworkScanner()
        self.is_scanning = False
        
        self.setup_ui()
    
    def setup_ui(self):
        network_frame = ttk.LabelFrame(self.root, text="Информация о сети")
        network_frame.pack(padx=10, pady=5, fill="x")
        
        self.network_label = ttk.Label(network_frame, text="Сеть: Не определена")
        self.network_label.pack(anchor="w", padx=5, pady=5)
        
        self.scan_button = ttk.Button(self.root, text="Сканировать", command=self.start_scan)
        self.scan_button.pack(pady=5)
        
        self.progress = ttk.Progressbar(self.root, mode="indeterminate")
        self.progress.pack(fill="x", padx=10, pady=5)
        
        self.result_text = scrolledtext.ScrolledText(self.root, height=15, width=60, state="disabled")
        self.result_text.pack(padx=10, pady=5, fill="both", expand=True)
        
        action_frame = ttk.LabelFrame(self.root, text="Действия с IP")
        action_frame.pack(padx=10, pady=5, fill="x")
        
        self.ip_entry = ttk.Entry(action_frame, width=20)
        self.ip_entry.pack(side="left", padx=5)
        
        ttk.Button(action_frame, text="Пинг", command=self.ping_ip).pack(side="left", padx=5)
        ttk.Button(action_frame, text="Открыть в браузере", command=self.open_in_browser).pack(side="left", padx=5)
        
        self.update_network_info()
    
    def update_network_info(self):
        network, netmask = self.scanner.get_network_info()
        if network and netmask:
            self.network_label.config(text=f"Сеть: {network}/{ipaddress.IPv4Network(f'0.0.0.0/{netmask}').prefixlen}")
        else:
            self.network_label.config(text="Сеть: Не удалось определить")
    
    def start_scan(self):
        if self.is_scanning:
            messagebox.showinfo("Информация", "Сканирование уже выполняется!")
            return
        
        self.is_scanning = True
        self.scan_button.config(state="disabled")
        self.progress.start()
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        self.result_text.config(state="disabled")
        
        network, netmask = self.scanner.get_network_info()
        if not network or not netmask:
            messagebox.showerror("Ошибка", "Не удалось определить сеть!")
            self.stop_scan()
            return
        
        threading.Thread(target=self.scan_thread, args=(network, netmask), daemon=True).start()
    
    def scan_thread(self, network: str, netmask: str):
        hosts = self.scanner.scan_network(network, netmask)
        self.root.after(0, self.display_results, hosts)
    
    def display_results(self, hosts: list):
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        
        if not hosts:
            self.result_text.insert(tk.END, "Активные хосты не найдены.\n")
        else:
            self.result_text.insert(tk.END, "Активные хосты:\n")
            for ip, mac in hosts:
                self.result_text.insert(tk.END, f"IP: {ip}, MAC: {mac}\n")
        
        self.result_text.config(state="disabled")
        self.stop_scan()
    
    def stop_scan(self):
        self.is_scanning = False
        self.scan_button.config(state="normal")
        self.progress.stop()
    
    def ping_ip(self):
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showwarning("Предупреждение", "Введите IP-адрес!")
            return
        
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            messagebox.showerror("Ошибка", "Некорректный IP-адрес!")
            return
        
        if self.scanner.ping_ip(ip):
            messagebox.showinfo("Результат", f"Хост {ip} отвечает на пинг.")
        else:
            messagebox.showinfo("Результат", f"Хост {ip} не отвечает на пинг.")
    
    def open_in_browser(self):
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showwarning("Предупреждение", "Введите IP-адрес!")
            return
        
        try:
            ipaddress.ip_address(ip)
            webbrowser.open(f"http://{ip}")
        except ValueError:
            messagebox.showerror("Ошибка", "Некорректный IP-адрес!")