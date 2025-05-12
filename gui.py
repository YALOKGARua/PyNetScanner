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
from datetime import datetime
from tkinter import PhotoImage
from ttkthemes import ThemedTk
import os
import netifaces

class NetworkScannerGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("PyNetScanner")
        self.root.geometry("1024x768")
        self.scanner = NetworkScanner()
        self.is_scanning = False
        self.history = []
        
        self.setup_styles()
        self.setup_ui()
        self.load_history()
        self.update_network_info()

    def setup_styles(self):
        style = ttk.Style()
        style.configure("Action.TButton", padding=5)
        style.configure("Scan.TButton", padding=10)
        style.configure("Info.TLabel")
        style.configure("Header.TLabel", font=("TkDefaultFont", 12, "bold"))

    def setup_ui(self):
        self.create_menu()
        
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side="left", fill="both", expand=True)
        
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side="right", fill="both", expand=True)
        
        self.setup_network_info(left_frame)
        self.setup_scan_controls(left_frame)
        self.setup_results_area(left_frame)
        self.setup_action_frame(left_frame)
        self.setup_history_frame(right_frame)
        self.setup_graph_frame(right_frame)

    def create_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Save Results", command=self.save_results_gui)
        file_menu.add_command(label="Export History", command=self.export_history)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Network Info", command=self.show_network_details)
        tools_menu.add_command(label="Clear History", command=self.clear_history)
        
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)

    def setup_network_info(self, parent):
        network_frame = ttk.LabelFrame(parent, text="Network Information")
        network_frame.pack(fill="x", padx=5, pady=5)
        
        self.network_label = ttk.Label(network_frame, text="Network: Not detected", style="Info.TLabel")
        self.network_label.pack(anchor="w", padx=5, pady=5)
        
        self.gateway_label = ttk.Label(network_frame, text="Gateway: Not detected", style="Info.TLabel")
        self.gateway_label.pack(anchor="w", padx=5, pady=5)

    def setup_scan_controls(self, parent):
        control_frame = ttk.LabelFrame(parent, text="Scan Controls")
        control_frame.pack(fill="x", padx=5, pady=5)
        
        self.scan_button = ttk.Button(control_frame, text="ARP Scan", 
                                    command=self.start_arp_scan, style="Scan.TButton")
        self.scan_button.pack(side="left", padx=5, pady=5)
        CreateToolTip(self.scan_button, "Perform ARP scan to discover active hosts")
        
        self.ping_scan_button = ttk.Button(control_frame, text="Ping Scan",
                                         command=self.start_ping_scan, style="Scan.TButton")
        self.ping_scan_button.pack(side="left", padx=5, pady=5)
        CreateToolTip(self.ping_scan_button, "Perform ICMP ping scan")
        
        self.extended_scan_button = ttk.Button(control_frame, text="Extended Scan",
                                             command=self.start_extended_scan, style="Scan.TButton")
        self.extended_scan_button.pack(side="left", padx=5, pady=5)
        CreateToolTip(self.extended_scan_button, "Perform comprehensive network scan")
        
        self.progress = ttk.Progressbar(control_frame, mode="indeterminate")
        self.progress.pack(fill="x", padx=5, pady=5)

    def setup_results_area(self, parent):
        results_frame = ttk.LabelFrame(parent, text="Scan Results")
        results_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.result_text = scrolledtext.ScrolledText(results_frame, height=15, font=("Consolas", 10))
        self.result_text.pack(fill="both", expand=True, padx=5, pady=5)

    def setup_action_frame(self, parent):
        action_frame = ttk.LabelFrame(parent, text="Host Actions")
        action_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(action_frame, text="IP Address:", style="Info.TLabel").pack(side="left", padx=5)
        
        self.ip_entry = ttk.Entry(action_frame, width=20)
        self.ip_entry.pack(side="left", padx=5)
        
        ttk.Button(action_frame, text="Ping", command=self.ping_ip,
                  style="Action.TButton").pack(side="left", padx=2)
        ttk.Button(action_frame, text="Web", command=self.open_in_browser,
                  style="Action.TButton").pack(side="left", padx=2)
        ttk.Button(action_frame, text="Ports", command=self.scan_single_host,
                  style="Action.TButton").pack(side="left", padx=2)

    def setup_history_frame(self, parent):
        history_frame = ttk.LabelFrame(parent, text="Scan History")
        history_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.history_text = scrolledtext.ScrolledText(history_frame, height=10, font=("Consolas", 9))
        self.history_text.pack(fill="both", expand=True, padx=5, pady=5)

    def setup_graph_frame(self, parent):
        self.graph_frame = ttk.LabelFrame(parent, text="Network Visualization")
        self.graph_frame.pack(fill="both", expand=True, padx=5, pady=5)

    def update_network_info(self):
        network, netmask = self.scanner.get_network_info()
        if network and netmask:
            prefix = ipaddress.IPv4Network(f'0.0.0.0/{netmask}').prefixlen
            self.network_label.config(text=f"Network: {network}/{prefix}")
            
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                gateway = gateways['default'][netifaces.AF_INET][0]
                self.gateway_label.config(text=f"Gateway: {gateway}")
        else:
            self.network_label.config(text="Network: Detection failed")
            self.gateway_label.config(text="Gateway: Not detected")

    def start_arp_scan(self):
        if self.is_scanning:
            messagebox.showinfo("Info", "Scan in progress!")
            return
        
        self.is_scanning = True
        self.scan_button.config(state="disabled")
        self.progress.start()
        self.clear_results()
        
        network, netmask = self.scanner.get_network_info()
        if not network or not netmask:
            messagebox.showerror("Error", "Failed to detect network!")
            self.stop_scan()
            return
        
        threading.Thread(target=self.scan_arp_thread, args=(network, netmask),
                       daemon=True).start()

    def scan_arp_thread(self, network: str, netmask: str):
        hosts = self.scanner.scan_network_arp(network, netmask)
        self.root.after(0, self.display_results, hosts)

    def start_ping_scan(self):
        if self.is_scanning:
            messagebox.showinfo("Info", "Scan in progress!")
            return
        
        self.is_scanning = True
        self.ping_scan_button.config(state="disabled")
        self.progress.start()
        self.clear_results()
        
        network, netmask = self.scanner.get_network_info()
        if not network or not netmask:
            messagebox.showerror("Error", "Failed to detect network!")
            self.stop_scan()
            return
        
        threading.Thread(target=self.scan_ping_thread, args=(network, netmask),
                       daemon=True).start()

    def scan_ping_thread(self, network: str, netmask: str):
        hosts = self.scanner.scan_network_ping(network, netmask)
        self.root.after(0, self.display_ping_results, hosts)

    def start_extended_scan(self):
        if self.is_scanning:
            messagebox.showinfo("Info", "Scan in progress!")
            return
        
        self.is_scanning = True
        self.extended_scan_button.config(state="disabled")
        self.progress.start()
        self.clear_results()
        
        network, netmask = self.scanner.get_network_info()
        if not network or not netmask:
            messagebox.showerror("Error", "Failed to detect network!")
            self.stop_scan()
            return
        
        self.scanner.run_extended_scan_thread(network, netmask, self.display_extended_results)

    def clear_results(self):
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        self.result_text.config(state="disabled")

    def display_results(self, hosts: list):
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        
        if not hosts:
            self.result_text.insert(tk.END, "No active hosts found (ARP)\n")
        else:
            self.result_text.insert(tk.END, "Active Hosts (ARP):\n")
            self.result_text.insert(tk.END, "-" * 60 + "\n")
            self.result_text.insert(tk.END, f"{'IP Address':<15} {'MAC Address':<17} {'Vendor':<20}\n")
            self.result_text.insert(tk.END, "-" * 60 + "\n")
            for ip, mac, vendor in hosts:
                self.result_text.insert(tk.END, f"{ip:<15} {mac:<17} {vendor:<20}\n")
        
        self.result_text.config(state="disabled")
        self.plot_graph(hosts)
        self.stop_scan()

    def display_ping_results(self, hosts: list):
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        
        if not hosts:
            self.result_text.insert(tk.END, "No active hosts found (Ping)\n")
        else:
            self.result_text.insert(tk.END, "Active Hosts (Ping):\n")
            self.result_text.insert(tk.END, "-" * 20 + "\n")
            for ip in hosts:
                self.result_text.insert(tk.END, f"{ip}\n")
        
        self.result_text.config(state="disabled")
        self.stop_scan()

    def display_extended_results(self, results: dict):
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        
        self.result_text.insert(tk.END, "Extended Scan Results:\n")
        self.result_text.insert(tk.END, f"Timestamp: {results['timestamp']}\n")
        self.result_text.insert(tk.END, f"Network: {results['network']}\n\n")
        
        self.result_text.insert(tk.END, "ARP Hosts:\n")
        self.result_text.insert(tk.END, "-" * 60 + "\n")
        for ip, mac, vendor in results["arp_hosts"]:
            self.result_text.insert(tk.END, f"{ip:<15} {mac:<17} {vendor:<20}\n")
        
        self.result_text.insert(tk.END, "\nPing Hosts:\n")
        self.result_text.insert(tk.END, "-" * 20 + "\n")
        for ip in results["ping_hosts"]:
            self.result_text.insert(tk.END, f"{ip}\n")
        
        self.result_text.insert(tk.END, "\nPort Scans:\n")
        self.result_text.insert(tk.END, "-" * 60 + "\n")
        for ip, ports in results["port_scans"].items():
            self.result_text.insert(tk.END, f"\nHost: {ip}\n")
            self.result_text.insert(tk.END, f"{'Port':<6} {'State':<8} {'Service':<15} {'Version':<20}\n")
            self.result_text.insert(tk.END, "-" * 60 + "\n")
            for port, info in ports.items():
                self.result_text.insert(tk.END,
                    f"{port:<6} {info['state']:<8} {info['service']:<15} {info['version']:<20}\n")
        
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
            messagebox.showwarning("Warning", "Enter an IP address!")
            return
        
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            messagebox.showerror("Error", "Invalid IP address!")
            return
        
        if self.scanner.ping_ip(ip):
            messagebox.showinfo("Result", f"Host {ip} is responding")
        else:
            messagebox.showinfo("Result", f"Host {ip} is not responding")

    def scan_single_host(self):
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showwarning("Warning", "Enter an IP address!")
            return
        
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            messagebox.showerror("Error", "Invalid IP address!")
            return
        
        ports = self.scanner.scan_ports(ip)
        if ports:
            self.result_text.config(state="normal")
            self.result_text.delete("1.0", tk.END)
            self.result_text.insert(tk.END, f"Port Scan Results for {ip}:\n")
            self.result_text.insert(tk.END, "-" * 60 + "\n")
            self.result_text.insert(tk.END, f"{'Port':<6} {'State':<8} {'Service':<15} {'Version':<20}\n")
            self.result_text.insert(tk.END, "-" * 60 + "\n")
            
            for port, info in ports.items():
                self.result_text.insert(tk.END,
                    f"{port:<6} {info['state']:<8} {info['service']:<15} {info['version']:<20}\n")
            
            self.result_text.config(state="disabled")
        else:
            messagebox.showinfo("Result", f"No open ports found on {ip}")

    def open_in_browser(self):
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showwarning("Warning", "Enter an IP address!")
            return
        
        try:
            ipaddress.ip_address(ip)
            webbrowser.open(f"http://{ip}")
        except ValueError:
            messagebox.showerror("Error", "Invalid IP address!")

    def save_results_gui(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if filename:
            self.scanner.save_results(filename, self.scanner.active_hosts)
            messagebox.showinfo("Success", f"Results saved to {filename}")

    def export_history(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.history, f, indent=4, ensure_ascii=False)
            messagebox.showinfo("Success", f"History exported to {filename}")

    def clear_history(self):
        if messagebox.askyesno("Confirm", "Clear all scan history?"):
            self.history = []
            if os.path.exists('scan_history.json'):
                os.remove('scan_history.json')
            self.update_history_display()

    def load_history(self):
        self.history = self.scanner.load_history()
        self.update_history_display()

    def update_history_display(self):
        self.history_text.config(state="normal")
        self.history_text.delete("1.0", tk.END)
        
        for entry in reversed(self.history):
            self.history_text.insert(tk.END, f"Time: {entry['timestamp']}\n")
            self.history_text.insert(tk.END, f"Network: {entry['network']}\n")
            self.history_text.insert(tk.END, "Hosts:\n")
            for host in entry['hosts']:
                self.history_text.insert(tk.END,
                    f"  {host['ip']:<15} {host['mac']:<17} {host['vendor']:<20}\n")
            self.history_text.insert(tk.END, "-" * 60 + "\n")
        
        self.history_text.config(state="disabled")

    def plot_graph(self, hosts: list):
        for widget in self.graph_frame.winfo_children():
            widget.destroy()
        
        if not hosts:
            return
            
        fig, ax = plt.subplots(figsize=(8, 4))
        ips = [ip for ip, _, _ in hosts]
        vendors = [vendor for _, _, vendor in hosts]
        x = range(len(ips))
        
        bars = ax.bar(x, [1] * len(ips), align='center')
        ax.set_xticks(x)
        ax.set_xticklabels(ips, rotation=45, ha='right')
        
        for i, (bar, vendor) in enumerate(zip(bars, vendors)):
            bar.set_color(plt.cm.Set3(i / len(hosts)))
            if vendor != "Unknown":
                ax.text(i, 0.5, vendor, ha='center', va='center',
                       rotation=90, fontsize=8)
        
        ax.set_title("Active Hosts Distribution")
        ax.set_ylabel("Status")
        plt.tight_layout()
        
        canvas = FigureCanvasTkAgg(fig, master=self.graph_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)

    def show_network_details(self):
        network, netmask = self.scanner.get_network_info()
        if network and netmask:
            network_obj = ipaddress.IPv4Network(f"{network}/{netmask}", strict=False)
            details = (
                f"Network Address: {network_obj.network_address}\n"
                f"Broadcast Address: {network_obj.broadcast_address}\n"
                f"Netmask: {network_obj.netmask}\n"
                f"Prefix Length: /{network_obj.prefixlen}\n"
                f"Number of Hosts: {network_obj.num_addresses - 2}\n"
                f"Address Range: {network_obj.network_address + 1} - {network_obj.broadcast_address - 1}"
            )
            messagebox.showinfo("Network Details", details)
        else:
            messagebox.showerror("Error", "Failed to detect network!")

    def show_about(self):
        about_text = """
PyNetScanner v1.0

A powerful network scanning utility for discovering and analyzing network hosts.

Features:
- ARP and Ping scanning
- Port scanning with service detection
- Network visualization
- History tracking
- MAC vendor identification

Created by YALOKGARua
        """
        messagebox.showinfo("About PyNetScanner", about_text)

class CreateToolTip(object):
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.widget.bind("<Enter>", self.enter)
        self.widget.bind("<Leave>", self.leave)
        self.tw = None

    def enter(self, event=None):
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 20
        self.tw = tk.Toplevel(self.widget)
        self.tw.wm_overrideredirect(True)
        self.tw.wm_geometry(f"+{x}+{y}")
        label = ttk.Label(self.tw, text=self.text, justify='left',
                         background="#ffffff", relief='solid', borderwidth=1)
        label.pack(ipadx=1)

    def leave(self, event=None):
        if self.tw:
            self.tw.destroy()
            self.tw = None