import tkinter as tk
from gui import NetworkScannerGUI
import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('network_scanner.log')
    ]
)

def main():
    try:
        root = tk.Tk()
        root.title("PyNetScanner")
        root.minsize(800, 600)
        app = NetworkScannerGUI(root)
        root.mainloop()
    except Exception as e:
        logging.error(f"Application error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()