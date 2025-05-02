# PyNetScanner

## Overview
PyNetScanner is a network scanning utility that allows you to discover active hosts in your local network. It provides a user-friendly graphical interface (GUI) built with Tkinter, supports both ARP and Ping scanning methods, and includes advanced features like port scanning, result visualization, and history management. The tool is designed for network administrators, security enthusiasts, and anyone interested in network exploration.

## Features
- **ARP Scanning**: Detects active devices using ARP requests.
- **Ping Scanning**: Alternative method to identify responsive hosts using ICMP.
- **Port Scanning**: Checks common ports (21, 22, 80, 443, 3389, 8080) on detected hosts.
- **Graphical Interface**: Intuitive GUI for easy operation.
- **Result Visualization**: Displays active hosts in a bar graph using Matplotlib.
- **Data Export**: Saves scan results to CSV files.
- **History Tracking**: Maintains a history of scans in JSON format.
- **Cross-Platform**: Works on Windows, Linux, and macOS (with proper dependencies).

## Requirements
- Python 3.13.2
- Required packages (install via `pip`):
  - `scapy==2.5.0`
  - `netifaces==0.11.0`
  - `matplotlib==3.9.2`
  - `numpy==2.0.0`

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/YALOKGARua/PyNetScanner.git
   cd PyNetScanner
