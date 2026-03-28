"""
Author: Felipe da Rocha Vieira Mattos
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime

# Print Python version and OS name
print(f"Python Version: {platform.python_version()}")
print(f"Operating System: {os.name}")

# Dictionary mapping common port numbers to their service names
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}


class NetworkTool:
    """Parent class providing basic network tool functionality."""

    def __init__(self, target):
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?
    # Using @property and @target.setter encapsulates the private attribute self.__target,
    # preventing external code from accessing or modifying it directly without going through
    # the defined getter and setter logic. This allows us to add validation in the setter
    # (such as rejecting empty strings) without changing how the attribute appears to be
    # accessed from outside the class — it still looks like a simple attribute, not a method call.
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
        else:
            self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")


# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner inherits from NetworkTool using class PortScanner(NetworkTool), which means
# it automatically gains access to the target property (getter and setter) and the private
# self.__target storage defined in NetworkTool without needing to rewrite that logic.
# For example, when the PortScanner constructor calls super().__init__(target), it reuses
# NetworkTool's constructor to store and validate the target IP address, and the
# self.target property is immediately available on any PortScanner instance.
class PortScanner(NetworkTool):
    """Child class that scans ports on a target machine."""

    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):
        """Scan a single port and record the result."""
        # Q4: What would happen without try-except here?
        # Without try-except blocks in scan_port, any network error — such as a connection
        # timeout, a refused connection, or an unreachable host — would raise an unhandled
        # exception and crash the entire thread, and potentially the whole program.
        # Since scan_port is run inside threads, an unhandled exception would silently kill
        # that thread without recording a result, making the scan incomplete and unreliable.
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            status = "Open" if result == 0 else "Closed"
            service_name = common_ports.get(port, "Unknown")
            self.lock.acquire()
            self.scan_results.append((port, status, service_name))
            self.lock.release()
        except socket.error as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            if sock:
                sock.close()

    def get_open_ports(self):
        """Return only open port results using a list comprehension."""
        return [result for result in self.scan_results if result[1] == "Open"]

    # Q2: Why do we use threading instead of scanning one port at a time?
    # Threading allows multiple ports to be scanned concurrently rather than waiting
    # for each connection attempt to time out before moving on to the next port.
    # Each port scan can take up to 1 second to time out; without threads, scanning
    # 1024 ports sequentially could take over 17 minutes in the worst case.
    # With threads, all 1024 scans run simultaneously (or near-simultaneously), reducing
    # total scan time to roughly the duration of a single timeout — about 1 second.
    def scan_range(self, start_port, end_port):
        """Scan a range of ports using threads."""
        threads = []
        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()


def save_results(target, results):
    """Save scan results to the SQLite database."""
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            port INTEGER,
            status TEXT,
            service TEXT,
            scan_date TEXT
        )""")
        for result in results:
            port, status, service = result
            cursor.execute(
                "INSERT INTO scans (target, port, status, service, scan_date) VALUES (?, ?, ?, ?, ?)",
                (target, port, status, service, str(datetime.datetime.now()))
            )
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"Database error: {e}")


def load_past_scans():
    """Load and display past scan results from the SQLite database."""
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()
        if not rows:
            print("No past scans found.")
        else:
            for row in rows:
                _, target, port, status, service, scan_date = row
                print(f"[{scan_date}] {target} : Port {port} ({service}) - {status}")
        conn.close()
    except sqlite3.Error:
        print("No past scans found.")


if __name__ == "__main__":
    # Get target IP
    target_input = input("Enter target IP address (press Enter for 127.0.0.1): ").strip()
    target = target_input if target_input else "127.0.0.1"

    # Get start port
    start_port = None
    while start_port is None:
        try:
            start_port = int(input("Enter start port (1-1024): "))
            if not (1 <= start_port <= 1024):
                print("Port must be between 1 and 1024.")
                start_port = None
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

    # Get end port
    end_port = None
    while end_port is None:
        try:
            end_port = int(input("Enter end port (1-1024): "))
            if not (1 <= end_port <= 1024):
                print("Port must be between 1 and 1024.")
                end_port = None
            elif end_port < start_port:
                print("End port must be greater than or equal to start port.")
                end_port = None
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

    # Create scanner and run
    scanner = PortScanner(target)
    print(f"Scanning {target} from port {start_port} to {end_port}...")
    scanner.scan_range(start_port, end_port)

    open_ports = scanner.get_open_ports()
    print(f"\n--- Scan Results for {target} ---")
    for port, status, service in open_ports:
        print(f"Port {port}: Open ({service})")
    print("------")
    print(f"Total open ports found: {len(open_ports)}")

    save_results(target, scanner.scan_results)

    history_choice = input("\nWould you like to see past scan history? (yes/no): ").strip().lower()
    if history_choice == "yes":
        load_past_scans()


# Q5: New Feature Proposal
# I would add a vulnerability hint feature that checks each open port against a dictionary
# of known vulnerable services and flags them with a warning message using a nested if-statement:
# if the port is open, it checks if the service (e.g., Telnet on port 23, FTP on port 21)
# is in a list of insecure_services, and if so, prints a warning like "WARNING: Telnet is
# unencrypted and considered insecure." This would help users immediately understand which
# open ports represent security risks without needing external tools.
# Diagram: See diagram_101581203.png in the repository root