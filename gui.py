import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import webbrowser
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from scanner import NetworkScanner
import ipaddress
import logging
import json
import time
import random

class NetworkScannerGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("PyNetScanner")
        self.root.geometry("800x600")
        self.scanner = NetworkScanner()
        self.is_scanning = False
        self.history = []
        
        self.setup_ui()
        self.load_history()

    def setup_ui(self):
        network_frame = ttk.LabelFrame(self.root, text="Информация о сети")
        network_frame.pack(padx=10, pady=5, fill="x")
        
        self.network_label = ttk.Label(network_frame, text="Сеть: Не определена")
        self.network_label.pack(anchor="w", padx=5, pady=5)
        
        self.scan_button = ttk.Button(self.root, text="Сканировать ARP", command=self.start_arp_scan)
        self.scan_button.pack(pady=5)
        
        self.ping_scan_button = ttk.Button(self.root, text="Сканировать Ping", command=self.start_ping_scan)
        self.ping_scan_button.pack(pady=5)
        
        self.extended_scan_button = ttk.Button(self.root, text="Расширенное сканирование", command=self.start_extended_scan)
        self.extended_scan_button.pack(pady=5)
        
        self.progress = ttk.Progressbar(self.root, mode="indeterminate")
        self.progress.pack(fill="x", padx=10, pady=5)
        
        self.result_text = scrolledtext.ScrolledText(self.root, height=15, width=80, state="disabled")
        self.result_text.pack(padx=10, pady=5, fill="both", expand=True)
        
        action_frame = ttk.LabelFrame(self.root, text="Действия с IP")
        action_frame.pack(padx=10, pady=5, fill="x")
        
        self.ip_entry = ttk.Entry(action_frame, width=20)
        self.ip_entry.pack(side="left", padx=5)
        
        ttk.Button(action_frame, text="Пинг", command=self.ping_ip).pack(side="left", padx=5)
        ttk.Button(action_frame, text="Открыть в браузере", command=self.open_in_browser).pack(side="left", padx=5)
        ttk.Button(action_frame, text="Сохранить результаты", command=self.save_results_gui).pack(side="left", padx=5)
        
        history_frame = ttk.LabelFrame(self.root, text="История сканирований")
        history_frame.pack(padx=10, pady=5, fill="both", expand=True)
        
        self.history_text = scrolledtext.ScrolledText(history_frame, height=10, width=80, state="disabled")
        self.history_text.pack(padx=5, pady=5, fill="both", expand=True)
        
        self.graph_frame = ttk.Frame(self.root)
        self.graph_frame.pack(padx=10, pady=5, fill="both", expand=True)
        
        self.update_network_info()

    def update_network_info(self):
        network, netmask = self.scanner.get_network_info()
        if network and netmask:
            self.network_label.config(text=f"Сеть: {network}/{ipaddress.IPv4Network(f'0.0.0.0/{netmask}').prefixlen}")
        else:
            self.network_label.config(text="Сеть: Не удалось определить")

    def start_arp_scan(self):
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
        
        threading.Thread(target=self.scan_arp_thread, args=(network, netmask), daemon=True).start()

    def scan_arp_thread(self, network: str, netmask: str):
        hosts = self.scanner.scan_network_arp(network, netmask)
        self.root.after(0, self.display_results, hosts)

    def start_ping_scan(self):
        if self.is_scanning:
            messagebox.showinfo("Информация", "Сканирование уже выполняется!")
            return
        
        self.is_scanning = True
        self.ping_scan_button.config(state="disabled")
        self.progress.start()
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        self.result_text.config(state="disabled")
        
        network, netmask = self.scanner.get_network_info()
        if not network or not netmask:
            messagebox.showerror("Ошибка", "Не удалось определить сеть!")
            self.stop_scan()
            return
        
        threading.Thread(target=self.scan_ping_thread, args=(network, netmask), daemon=True).start()

    def scan_ping_thread(self, network: str, netmask: str):
        hosts = self.scanner.scan_network_ping(network, netmask)
        self.root.after(0, self.display_ping_results, hosts)

    def start_extended_scan(self):
        if self.is_scanning:
            messagebox.showinfo("Информация", "Сканирование уже выполняется!")
            return
        
        self.is_scanning = True
        self.extended_scan_button.config(state="disabled")
        self.progress.start()
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        self.result_text.config(state="disabled")
        
        network, netmask = self.scanner.get_network_info()
        if not network or not netmask:
            messagebox.showerror("Ошибка", "Не удалось определить сеть!")
            self.stop_scan()
            return
        
        self.scanner.run_extended_scan_thread(network, netmask, self.display_extended_results)

    def display_results(self, hosts: list):
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        
        if not hosts:
            self.result_text.insert(tk.END, "Активные хосты не найдены (ARP).\n")
        else:
            self.result_text.insert(tk.END, "Активные хосты (ARP):\n")
            for ip, mac in hosts:
                self.result_text.insert(tk.END, f"IP: {ip}, MAC: {mac}\n")
        
        self.result_text.config(state="disabled")
        self.plot_graph(hosts)
        self.stop_scan()

    def display_ping_results(self, hosts: list):
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        
        if not hosts:
            self.result_text.insert(tk.END, "Активные хосты не найдены (Ping).\n")
        else:
            self.result_text.insert(tk.END, "Активные хосты (Ping):\n")
            for ip in hosts:
                self.result_text.insert(tk.END, f"IP: {ip}\n")
        
        self.result_text.config(state="disabled")
        self.stop_scan()

    def display_extended_results(self, results: dict):
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        
        self.result_text.insert(tk.END, "Расширенные результаты:\n")
        self.result_text.insert(tk.END, "ARP хосты:\n")
        for ip, mac in results["arp_hosts"]:
            self.result_text.insert(tk.END, f"IP: {ip}, MAC: {mac}\n")
        
        self.result_text.insert(tk.END, "Ping хосты:\n")
        for ip in results["ping_hosts"]:
            self.result_text.insert(tk.END, f"IP: {ip}\n")
        
        self.result_text.insert(tk.END, "Порты:\n")
        for ip, ports in results["port_scans"].items():
            self.result_text.insert(tk.END, f"IP: {ip}\n")
            for port, open in ports.items():
                self.result_text.insert(tk.END, f"Порт {port}: {'Открыт' if open else 'Закрыт'}\n")
        
        self.result_text.config(state="disabled")
        self.plot_graph(results["arp_hosts"])
        self.stop_scan()

    def stop_scan(self):
        self.is_scanning = False
        self.scan_button.config(state="normal")
        self.ping_scan_button.config(state="normal")
        self.extended_scan_button.config(state="normal")
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

    def save_results_gui(self):
        filename = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if filename:
            self.scanner.save_results(filename, self.scanner.active_hosts)
            messagebox.showinfo("Успех", f"Результаты сохранены в {filename}")

    def load_history(self):
        self.history = self.scanner.load_history()
        self.update_history_display()

    def update_history_display(self):
        self.history_text.config(state="normal")
        self.history_text.delete("1.0", tk.END)
        for entry in self.history:
            self.history_text.insert(tk.END, f"Время: {entry['timestamp']}\n")
            self.history_text.insert(tk.END, f"Сеть: {entry['network']}\n")
            self.history_text.insert(tk.END, "Хосты:\n")
            for host in entry['hosts']:
                self.history_text.insert(tk.END, f"  IP: {host['ip']}, MAC: {host['mac']}\n")
            self.history_text.insert(tk.END, "-" * 50 + "\n")
        self.history_text.config(state="disabled")

    def plot_graph(self, hosts: list):
        for widget in self.graph_frame.winfo_children():
            widget.destroy()
        
        fig, ax = plt.subplots(figsize=(8, 6))
        ips = [ip for ip, _ in hosts]
        x = range(len(ips))
        ax.bar(x, [1] * len(ips), align='center')
        ax.set_xticks(x)
        ax.set_xticklabels(ips, rotation=45)
        ax.set_title("Активные хосты")
        ax.set_ylabel("Статус")
        
        canvas = FigureCanvasTkAgg(fig, master=self.graph_frame)
        canvas.draw()
        canvas.get_tk_widget().pack()

    def generate_dummy_data(self):
        for i in range(50):
            test_data = self.scanner.generate_test_data(5)
            for ip, mac in test_data:
                logging.info(f"Генерация данных GUI {i}: {ip}, {mac}")
                time.sleep(0.01)