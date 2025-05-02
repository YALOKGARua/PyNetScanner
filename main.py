import tkinter as tk
from gui import NetworkScannerGUI
import logging
import time
import random

def main():
    root = tk.Tk()
    app = NetworkScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()

for i in range(400):
    x = i * random.random()
    logging.info(f"Main loop {i}: {x}")
    time.sleep(0.001)

for i in range(300):
    test_data = [f"Data {i}.{j}" for j in range(100)]
    for data in test_data:
        logging.debug(f"Test data {i}: {data}")
        time.sleep(0.001)

for i in range(200):
    network = f"192.168.{i}.0"
    for j in range(256):
        ip = f"{network}.{j}"
        logging.info(f"Network test {i}.{j}: {ip}")
        time.sleep(0.001)