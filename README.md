# PyNetScanner

## Overview
PyNetScanner is a powerful network scanning utility with a modern graphical interface for discovering and analyzing devices in your local network. It provides comprehensive network scanning capabilities, including ARP scanning, ICMP ping scanning, and port scanning with service detection.

## Features
- **Modern GUI**: Clean and intuitive interface with dark theme support
- **Multiple Scanning Methods**:
  - ARP scanning for quick host discovery
  - ICMP ping scanning for network mapping
  - Port scanning with service version detection
  - Extended scanning combining multiple methods
- **Network Analysis**:
  - MAC address vendor identification
  - Service version detection
  - Network topology visualization
  - Detailed port state information
- **Data Management**:
  - CSV export of scan results
  - JSON-based scan history
  - Network information details
  - Customizable data visualization
- **Additional Tools**:
  - Individual host analysis
  - Web interface access
  - Network details viewer
  - History management

## Requirements
- Python 3.8+
- Required packages:
  ```
  scapy==2.5.0
  netifaces==0.11.0
  matplotlib==3.7.1
  numpy==1.24.3
  tkinter-tooltip==2.1.0
  pillow==10.0.0
  python-nmap==0.7.1
  psutil==5.9.5
  ```

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/YALOKGARua/PyNetScanner.git
   cd PyNetScanner
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Install additional requirements:
   - Windows: Install [Npcap](https://npcap.com/#download)
   - Linux: Install `nmap` and `tcpdump`
   ```bash
   sudo apt-get install nmap tcpdump
   ```

## Usage
1. Run the application:
   ```bash
   python main.py
   ```

2. The main window provides several scanning options:
   - **ARP Scan**: Quick discovery of active hosts using ARP
   - **Ping Scan**: Traditional ICMP ping sweep
   - **Extended Scan**: Comprehensive network analysis

3. Additional features:
   - Use the IP tools panel for individual host analysis
   - View scan history in the history panel
   - Export results to CSV or JSON
   - Analyze network visualization graphs

## Security Note
This tool is intended for network administrators and security professionals to analyze their own networks. Always ensure you have proper authorization before scanning any network.

## Contributing
Contributions are welcome! Please feel free to submit pull requests or create issues for bugs and feature requests.

## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Author
Created by YALOKGARua
