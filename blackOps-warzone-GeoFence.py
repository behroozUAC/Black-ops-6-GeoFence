import sys
import os
import subprocess
import ipaddress
import socket
import time
import json
import ctypes
from collections.abc import Iterable
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QListWidget,
    QMessageBox, QHBoxLayout, QComboBox, QTextEdit, QLineEdit, QListWidgetItem
)
from PySide6.QtCore import Qt, Signal, QObject, QThread, QTimer

IP_RANGES_FILE = "ip_ranges.json"

allowed_ips = [
    "185.34.106.26",
    "185.34.106.31",
    "185.34.107.128",
    "185.34.107.129"
]

COD_texture_streaming = {
    "ip_ranges": ["2.16.192.0-2.16.207.255", "2.19.126.208-2.19.126.215"]
}

class Communicate(QObject):
    log_signal = Signal(str)

def log_message(message):
    communicator.log_signal.emit(message)

communicator = Communicate()

def load_ip_ranges():
    if not os.path.exists(IP_RANGES_FILE):
        default_ip_ranges = {
            "Germany": {
                "domains": [],
                "ip_ranges": [
                    "13.32.0.0-13.32.255.255",
                    "146.0.0.0-146.0.255.255",
                    "45.158.0.0-45.158.255.255",
                    "173.244.0.0-173.244.255.255",
                    "95.179.0.0-95.179.255.255",
                    "199.247.0.0-199.247.255.255",
                    "173.199.0.0-173.199.255.255",
                    "80.240.0.0-80.240.255.255",
                    "85.195.0.0-85.195.255.255",
                    "104.238.0.0-104.238.255.255",
                    "140.82.0.0-140.82.255.255",
                    "192.248.0.0-192.248.255.255",
                    "195.0.0.0-195.255.255.255"
                ]
            },
            "France": {
                "domains": [],
                "ip_ranges": [
                    "92.204.0.0-92.204.255.255",
                    "95.179.0.0-95.179.255.255",
                    "136.244.0.0-136.244.255.255",
                    "45.63.0.0-45.63.255.255",
                    "45.76.0.0-45.76.255.255",
                    "45.77.0.0-45.77.255.255",
                    "45.0.0.0-45.255.255.255",
                    "92.42.0.0-92.42.255.255",
                    "107.191.0.0-107.191.255.255",
                    "108.61.0.0-108.61.255.255",
                    "217.69.0.0-217.69.255.255",
                    "134.119.0.0-134.119.255.255",
                    "143.244.0.0-143.244.255.255",
                    "5.188.92.0-5.188.92.255"
                ]
            },
            "Netherlands": {
                "domains": [],
                "ip_ranges": [
                    "23.0.0.0-23.255.255.255",
                    "88.202.0.0-88.202.255.255",
                    "185.80.0.0-185.80.255.255",
                    "5.200.0.0-5.200.255.255",
                    "46.23.0.0-46.23.255.255",
                    "188.42.241.0-188.42.241.255",
                    "78.141.0.0-78.141.255.255",
                    "31.204.0.0-31.204.255.255",
                    "188.42.40.0-188.42.47.255"
                ]
            },
            "UK": {
                "domains": [],
                "ip_ranges": [
                    "45.63.0.0-45.63.255.255",
                    "35.214.0.0-35.214.255.255",
                    "91.109.0.0-91.109.255.255",
                    "109.0.0.0-109.255.255.255",
                    "78.0.0.0-78.255.255.255",
                    "212.0.0.0-212.255.255.255",
                    "82.163.0.0-82.163.255.255",
                    "82.145.0.0-82.145.255.255",
                    "5.181.0.0-5.181.255.255",
                    "95.154.0.0-95.154.255.255"
                ]
            },
            "Spain": {
                "domains": [],
                "ip_ranges": [
                    "65.20.0.0-65.20.255.255",
                    "208.85.0.0-208.85.255.255",
                    "208.76.0.0-208.76.255.255"
                ]
            },
            "Italy": {
                "domains": [],
                "ip_ranges": [
                    "138.199.0.0-138.199.255.255",
                    "109.200.0.0-109.200.255.255"
                ]
            },
            "Bahrain": {
                "domains": [],
                "ip_ranges": [
                    "15.185.0.0-15.185.255.255",
                    "15.184.0.0-15.185.255.255"
                ]
            },
            "Belgium": {
                "domains": [],
                "ip_ranges": [
                    "35.210.0.0-35.210.255.255"
                ]
            },
            "Sweden": {
                "domains": [],
                "ip_ranges": [
                    "184.31.0.0-184.31.255.255",
                    "184.51.0.0-184.51.255.255"
                ]
            },
            "Finland": {
                "domains": [],
                "ip_ranges": [
                    "35.217.0.0-35.217.255.255",
                    "18.165.0.0-18.165.255.255"
                ]
            },
            "Luxembourg": {
                "domains": [],
                "ip_ranges": [
                    "188.42.0.0-188.42.255.255",
                    "188.42.188.0-188.42.191.255"
                ]
            },
            "Poland": {
                "domains": [],
                "ip_ranges": [
                    "70.34.0.0-70.34.255.255",
                    "64.176.0.0-64.176.255.255"
                ]
            },
            "Switzerland": {
                "domains": [],
                "ip_ranges": [
                    "35.216.0.0-35.216.255.255"
                ]
            },
            "COD_texture_streaming": {
                "ip_ranges": ["2.16.192.0-2.16.207.255",
                              "2.19.126.208-2.19.126.215",
                             "2.19.112.0-2.19.127.255"]
            }
        }
        with open(IP_RANGES_FILE, 'w') as f:
            json.dump(default_ip_ranges, f, indent=4)
        return default_ip_ranges
    else:
        with open(IP_RANGES_FILE, 'r') as f:
            return json.load(f)

def save_ip_ranges(ip_ranges):
    try:
        with open(IP_RANGES_FILE, 'w') as f:
            json.dump(ip_ranges, f, indent=4)
        log_message("IP ranges saved successfully.")
    except Exception as e:
        log_message(f"Failed to save IP ranges. Error: {e}")

ip_ranges = load_ip_ranges()

def rule_exists(display_name):
    try:
        result = subprocess.run(
            [
                "powershell",
                "-Command",
                f"Get-NetFirewallRule -DisplayName \"{display_name}\""
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        output = result.stdout.decode().strip()
        return bool(output)
    except subprocess.CalledProcessError:
        return False

def create_firewall_rule(action, direction, cidr, category, identifier):
    try:
        if isinstance(cidr, Iterable) and not isinstance(cidr, str):
            cidr_str = ",".join([str(c) for c in cidr])
        else:
            cidr_str = str(cidr)
        
        display_name = f"GeoFence-{category}-{direction}-{identifier}"
        
        if rule_exists(display_name):
            log_message(f"Rule '{display_name}' already exists. Skipping creation.")
            return
        
        subprocess.run(
            [
                "powershell",
                "-Command",
                f"New-NetFirewallRule -DisplayName \"{display_name}\" -Direction {direction} -RemoteAddress \"{cidr_str}\" -Action {action} -Profile Any -Enabled True"
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        log_message(f"Successfully {action.lower()}ed {direction.lower()} rule '{display_name}'.")
    except subprocess.CalledProcessError as e:
        error_message = e.stderr.decode().strip()
        log_message(f"Failed to {action.lower()} {direction.lower()} rule '{display_name}'. Error: {error_message}")

def remove_firewall_rule(category, direction, identifier):
    try:
        display_name = f"GeoFence-{category}-{direction}-{identifier}"
        
        subprocess.run(
            [
                "powershell",
                "-Command",
                f"Remove-NetFirewallRule -DisplayName \"{display_name}\""
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE
        )
        log_message(f"Successfully removed rule '{display_name}'.")
    except subprocess.CalledProcessError as e:
        error_message = e.stderr.decode().strip()
        log_message(f"Failed to remove rule '{display_name}'. Error: {error_message}")

def resolve_domain(domain):
    try:
        return list(set([result[4][0] for result in socket.getaddrinfo(domain, None) if result[4][0].startswith(tuple('123456789'))]))
    except socket.gaierror:
        log_message(f"Failed to resolve domain: {domain}")
        return []

def block_specific_domain(domain):
    ips = resolve_domain(domain)
    if not ips:
        log_message("No IPs found to block.")
        return
    for ip in ips:
        try:
            create_firewall_rule("Block", "Inbound", ip, "Domain", ip)
            create_firewall_rule("Block", "Outbound", ip, "Domain", ip)
        except Exception as e:
            log_message(f"Error blocking domain IP {ip}: {e}")

def unblock_specific_domain(domain):
    ips = resolve_domain(domain)
    if not ips:
        log_message("No IPs found to unblock.")
        return
    for ip in ips:
        try:
            remove_firewall_rule("Domain", "Inbound", ip)
            remove_firewall_rule("Domain", "Outbound", ip)
        except Exception as e:
            log_message(f"Error unblocking domain IP {ip}: {e}")

def block_country(country):
    ranges = ip_ranges.get(country, {}).get("ip_ranges", [])
    for ip_range_str in ranges:
        try:
            start_ip, end_ip = ip_range_str.split('-')
            cidr_list = list(ipaddress.summarize_address_range(ipaddress.IPv4Address(start_ip), ipaddress.IPv4Address(end_ip)))
            create_firewall_rule("Block", "Inbound", cidr_list, country, ip_range_str)
            create_firewall_rule("Block", "Outbound", cidr_list, country, ip_range_str)
        except Exception as e:
            log_message(f"Error blocking {country} {ip_range_str}: {e}")

def unblock_country(country):
    ranges = ip_ranges.get(country, {}).get("ip_ranges", [])
    for ip_range_str in ranges:
        try:
            remove_firewall_rule(country, "Inbound", ip_range_str)
            remove_firewall_rule(country, "Outbound", ip_range_str)
        except Exception as e:
            log_message(f"Error unblocking {country} {ip_range_str}: {e}")

def block_all_except(except_country):
    for country, data in ip_ranges.items():
        if country != except_country and country != "COD_texture_streaming":
            log_message(f"Blocking all IP ranges for: {country}")
            block_country(country)

def unblock_all_except(except_country):
    for country, data in ip_ranges.items():
        if country != except_country and country != "COD_texture_streaming":
            log_message(f"Unblocking all IP ranges for: {country}")
            unblock_country(country)

def unblock_all():
    for country in ip_ranges.keys():
        if country != "COD_texture_streaming":
            log_message(f"Unblocking all IP ranges for: {country}")
            unblock_country(country)

def block_all_non_uk():
    block_all_except("UK")

def remove_all_non_uk_blocks():
    unblock_all_except("UK")

def block_cod_texture_streaming():
    country = "COD_texture_streaming"
    ranges = ip_ranges.get(country, {}).get("ip_ranges", [])
    for ip_range_str in ranges:
        try:
            start_ip, end_ip = ip_range_str.split('-')
            cidr_list = list(ipaddress.summarize_address_range(ipaddress.IPv4Address(start_ip), ipaddress.IPv4Address(end_ip)))
            create_firewall_rule("Block", "Inbound", cidr_list, country, ip_range_str)
            create_firewall_rule("Block", "Outbound", cidr_list, country, ip_range_str)
        except Exception as e:
            log_message(f"Error blocking {country} {ip_range_str}: {e}")

def unblock_cod_texture_streaming():
    country = "COD_texture_streaming"
    ranges = ip_ranges.get(country, {}).get("ip_ranges", [])
    for ip_range_str in ranges:
        try:
            remove_firewall_rule(country, "Inbound", ip_range_str)
            remove_firewall_rule(country, "Outbound", ip_range_str)
        except Exception as e:
            log_message(f"Error unblocking {country} {ip_range_str}: {e}")

def setup_allowed_ips():
    log_message("Setting up allowed login servers...")
    for ip in allowed_ips:
        try:
            create_firewall_rule("Allow", "Inbound", ipaddress.IPv4Address(ip), "Allowed", ip)
            create_firewall_rule("Allow", "Outbound", ipaddress.IPv4Address(ip), "Allowed", ip)
        except Exception as e:
            log_message(f"Error setting up allowed IP {ip}: {e}")
    log_message("Setup complete.")

class Worker(QObject):
    finished = Signal()
    progress = Signal(str)
    
    def __init__(self, func, *args, **kwargs):
        super().__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs
    
    def run(self):
        try:
            self.func(*self.args, **self.kwargs)
        except Exception as e:
            log_message(f"Error in worker: {e}")
        self.finished.emit()

class FirewallManager(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("UAC COD GeoFence")
        self.setGeometry(100, 100, 1400, 1000)
        self.layout = QVBoxLayout()

        self.setup_title(self.layout)

        self.country_label = QLabel("Select Country:")
        self.layout.addWidget(self.country_label)

        self.country_combo = QComboBox()
        countries = sorted([country for country in ip_ranges.keys() if country != "COD_texture_streaming" and country != "Allowed"])
        self.country_combo.addItems(countries)
        self.country_combo.currentTextChanged.connect(self.update_ip_ranges)
        self.layout.addWidget(self.country_combo)

        self.ip_ranges_label = QLabel("IP Ranges:")
        self.layout.addWidget(self.ip_ranges_label)

        self.ip_ranges_list = QListWidget()
        self.layout.addWidget(self.ip_ranges_list)

        self.add_ip_layout = QHBoxLayout()
        self.new_ip_input = QLineEdit()
        self.new_ip_input.setPlaceholderText("Enter new IP range (start-end)")
        self.add_ip_btn = QPushButton("Add IP Range")
        self.add_ip_btn.clicked.connect(self.add_ip_range)
        self.add_ip_layout.addWidget(self.new_ip_input)
        self.add_ip_layout.addWidget(self.add_ip_btn)
        self.layout.addLayout(self.add_ip_layout)

        self.remove_ip_btn = QPushButton("Remove Selected IP Range")
        self.remove_ip_btn.clicked.connect(self.remove_ip_range)
        self.layout.addWidget(self.remove_ip_btn)

        self.button_layout = QHBoxLayout()

        self.block_btn = QPushButton("Block Country")
        self.block_btn.clicked.connect(self.block_country_ui)
        self.button_layout.addWidget(self.block_btn)

        self.unblock_btn = QPushButton("Unblock Country")
        self.unblock_btn.clicked.connect(self.unblock_country_ui)
        self.button_layout.addWidget(self.unblock_btn)

        self.layout.addLayout(self.button_layout)

        self.button_layout2 = QHBoxLayout()

        self.block_except_btn = QPushButton("Block All Except")
        self.block_except_btn.clicked.connect(self.block_all_except_ui)
        self.button_layout2.addWidget(self.block_except_btn)

        self.unblock_except_btn = QPushButton("Unblock All Except")
        self.unblock_except_btn.clicked.connect(self.unblock_all_except_ui)
        self.button_layout2.addWidget(self.unblock_except_btn)

        self.layout.addLayout(self.button_layout2)

        self.button_layout3 = QHBoxLayout()

        self.unblock_all_btn = QPushButton("Unblock All")
        self.unblock_all_btn.clicked.connect(self.unblock_all_ui)
        self.button_layout3.addWidget(self.unblock_all_btn)

        self.block_cod_btn = QPushButton("Block COD Streaming")
        self.block_cod_btn.clicked.connect(self.block_cod_ui)
        self.button_layout3.addWidget(self.block_cod_btn)

        self.unblock_cod_btn = QPushButton("Unblock COD Streaming")
        self.unblock_cod_btn.clicked.connect(self.unblock_cod_ui)
        self.button_layout3.addWidget(self.unblock_cod_btn)

        self.layout.addLayout(self.button_layout3)

        self.button_layout4 = QHBoxLayout()

        self.layout.addLayout(self.button_layout4)

        self.button_layout5 = QHBoxLayout()

        self.layout.addLayout(self.button_layout5)

        self.quit_btn = QPushButton("Quit")
        self.quit_btn.clicked.connect(self.close)
        self.layout.addWidget(self.quit_btn)

        self.log_label = QLabel("Log:")
        self.layout.addWidget(self.log_label)

        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setStyleSheet("background-color: #2b2b2b; color: #ffffff; font-family: Consolas; font-size: 12px;")
        self.log_area.setMinimumHeight(400)
        self.layout.addWidget(self.log_area)

        self.setLayout(self.layout)

        communicator.log_signal.connect(self.update_log)

        self.init_setup()

        self.apply_dark_theme()

        self.update_ip_ranges(self.country_combo.currentText())

        self.color_timer = QTimer(self)
        self.color_timer.timeout.connect(self.animate_title_color)
        self.color_timer.start(50)

    def setup_title(self, layout):
        self.title_label = QLabel("UAC COD GeoFence ")
        self.title_label.setStyleSheet("font-size: 20px; font-weight: bold; color: white; background-color: #1a1a1a; padding: 10px; border-radius: 8px;")
        self.title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.title_label)

        self.r, self.g, self.b = 255, 0, 0
        self.color_step = 1

    def animate_title_color(self):
        if self.r == 255 and self.g < 255 and self.b == 0:
            self.g += self.color_step
        elif self.g == 255 and self.r > 0 and self.b == 0:
            self.r -= self.color_step
        elif self.g == 255 and self.b < 255 and self.r == 0:
            self.b += self.color_step
        elif self.b == 255 and self.g > 0 and self.r == 0:
            self.g -= self.color_step
        elif self.b == 255 and self.r < 255 and self.g == 0:
            self.r += self.color_step
        elif self.r == 255 and self.b > 0 and self.g == 0:
            self.b -= self.color_step

        color = f"rgb({self.r}, {self.g}, {self.b})"
        self.title_label.setStyleSheet(f"font-size: 20px; font-weight: bold; color: {color}; background-color: #1a1a1a; padding: 10px; border-radius: 8px;")

    def apply_dark_theme(self):
        dark_stylesheet = """
            QWidget {
                background-color: #121212;
                color: #ffffff;
            }
            QPushButton {
                background-color: #1f1f1f;
                border: 1px solid #3a3a3a;
                padding: 5px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #2c2c2c;
            }
            QPushButton:pressed {
                background-color: #3a3a3a;
            }
            QComboBox {
                background-color: #1f1f1f;
                border: 1px solid #3a3a3a;
                padding: 5px;
                border-radius: 5px;
            }
            QListWidget {
                background-color: #1f1f1f;
                border: 1px solid #3a3a3a;
            }
            QLabel {
                color: #ffffff;
            }
            QLineEdit {
                background-color: #1f1f1f;
                color: #ffffff;
                border: 1px solid #3a3a3a;
                padding: 5px;
                border-radius: 5px;
            }
            QTextEdit {
                background-color: #2b2b2b;
                color: #ffffff;
                border: 1px solid #3a3a3a;
                padding: 5px;
                border-radius: 5px;
            }
            QMessageBox {
                background-color: #121212;
                color: #ffffff;
            }
        """
        self.setStyleSheet(dark_stylesheet)
    
    def update_log(self, message):
        self.log_area.append(message)
    
    def show_message(self, title, message):
        msg = QMessageBox()
        msg.setWindowTitle(title)
        msg.setText(message)
        msg.setStyleSheet("QMessageBox {background-color: #121212; color: #ffffff;} QPushButton {background-color: #1f1f1f; color: #ffffff;}")
        msg.exec()
    
    def disable_buttons(self):
        self.block_btn.setEnabled(False)
        self.unblock_btn.setEnabled(False)
        self.block_except_btn.setEnabled(False)
        self.unblock_except_btn.setEnabled(False)
        self.unblock_all_btn.setEnabled(False)
        self.block_cod_btn.setEnabled(False)
        self.unblock_cod_btn.setEnabled(False)
        self.add_ip_btn.setEnabled(False)
        self.remove_ip_btn.setEnabled(False)
        self.quit_btn.setEnabled(False)
    
    def enable_buttons(self):
        self.block_btn.setEnabled(True)
        self.unblock_btn.setEnabled(True)
        self.block_except_btn.setEnabled(True)
        self.unblock_except_btn.setEnabled(True)
        self.unblock_all_btn.setEnabled(True)
        self.block_cod_btn.setEnabled(True)
        self.unblock_cod_btn.setEnabled(True)
        self.add_ip_btn.setEnabled(True)
        self.remove_ip_btn.setEnabled(True)
        self.quit_btn.setEnabled(True)
    
    def run_in_thread(self, func, *args, **kwargs):
        self.disable_buttons()
        self.log_area.append("Operation started. Please wait...")
        
        self.thread = QThread()
        self.worker = Worker(func, *args, **kwargs)
        self.worker.moveToThread(self.thread)
        
        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.worker.finished.connect(self.operation_finished)
        
        self.thread.start()
    
    def operation_finished(self):
        self.enable_buttons()
        self.log_area.append("Operation completed.")
    
    def block_country_ui(self):
        country = self.country_combo.currentText()
        reply = QMessageBox.question(
            self, 'Confirm',
            f"Block all IP ranges for {country}?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.run_in_thread(block_country, country)
    
    def unblock_country_ui(self):
        country = self.country_combo.currentText()
        reply = QMessageBox.question(
            self, 'Confirm',
            f"Unblock all IP ranges for {country}?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.run_in_thread(unblock_country, country)
    
    def block_all_except_ui(self):
        country = self.country_combo.currentText()
        reply = QMessageBox.question(
            self, 'Confirm',
            f"Block all countries except {country}?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.run_in_thread(block_all_except, country)
    
    def unblock_all_except_ui(self):
        country = self.country_combo.currentText()
        reply = QMessageBox.question(
            self, 'Confirm',
            f"Unblock all countries except {country}?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.run_in_thread(unblock_all_except, country)
    
    def unblock_all_ui(self):
        reply = QMessageBox.question(
            self, 'Confirm',
            "Are you sure you want to unblock all IP ranges?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.run_in_thread(unblock_all)
    
    def block_cod_ui(self):
        reply = QMessageBox.question(
            self, 'Confirm',
            "Block COD texture streaming?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.run_in_thread(block_cod_texture_streaming)
    
    def unblock_cod_ui(self):
        reply = QMessageBox.question(
            self, 'Confirm',
            "Unblock COD texture streaming?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.run_in_thread(unblock_cod_texture_streaming)
    
    def block_non_uk_ui(self):
        reply = QMessageBox.question(
            self, 'Confirm',
            "Block all non-UK IP ranges?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.run_in_thread(block_all_non_uk)
    
    def remove_non_uk_ui(self):
        reply = QMessageBox.question(
            self, 'Confirm',
            "Remove all non-UK IP range blocks?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.run_in_thread(remove_all_non_uk_blocks)
    
    def update_ip_ranges(self, country):
        self.ip_ranges_list.clear()
        data = ip_ranges.get(country, {})
        domains = data.get("domains", [])
        ip_ranges_list = data.get("ip_ranges", [])
        if domains:
            self.ip_ranges_list.addItem("Domains:")
            for domain in domains:
                self.ip_ranges_list.addItem(f"  - {domain}")
        if ip_ranges_list:
            self.ip_ranges_list.addItem("IP Ranges:")
            for ip_range in ip_ranges_list:
                self.ip_ranges_list.addItem(f"  - {ip_range}")
    
    def add_ip_range(self):
        country = self.country_combo.currentText()
        new_entry = self.new_ip_input.text().strip()
        if not new_entry:
            self.show_message("Input Error", "Please enter a domain or IP range.")
            return
        if '-' in new_entry:
            if 'ip_ranges' in ip_ranges.get(country, {}):
                new_ip_range = new_entry
                start_end = new_ip_range.split('-', 1)
                if len(start_end) != 2:
                    self.show_message("Input Error", "Invalid IP range format. Use 'start-end'.")
                    return
                start_ip, end_ip = start_end
                try:
                    ipaddress.IPv4Address(start_ip.strip())
                    ipaddress.IPv4Address(end_ip.strip())
                    if ipaddress.IPv4Address(start_ip.strip()) > ipaddress.IPv4Address(end_ip.strip()):
                        self.show_message("Input Error", "Start IP must be less than or equal to End IP.")
                        return
                except ipaddress.AddressValueError:
                    self.show_message("Input Error", "Invalid IP address.")
                    return
                ip_ranges[country]["ip_ranges"].append(new_ip_range)
                self.ip_ranges_list.addItem(f"  - {new_ip_range}")
                save_ip_ranges(ip_ranges)
                self.show_message("Success", f"Added new IP range '{new_ip_range}' to {country}.")
            else:
                self.show_message("Data Error", "Invalid country data structure.")
        else:
            if 'domains' in ip_ranges.get(country, {}):
                new_domain = new_entry
                if not all(x.isalnum() or x in "-." for x in new_domain):
                    self.show_message("Input Error", "Invalid domain format.")
                    return
                ip_ranges[country]["domains"].append(new_domain)
                self.ip_ranges_list.addItem(f"  - {new_domain}")
                save_ip_ranges(ip_ranges)
                self.show_message("Success", f"Added new domain '{new_domain}' to {country}.")
            else:
                self.show_message("Data Error", "Invalid country data structure.")
        self.new_ip_input.clear()
    
    def remove_ip_range(self):
        country = self.country_combo.currentText()
        selected_items = self.ip_ranges_list.selectedItems()
        if not selected_items:
            self.show_message("Selection Error", "Please select an IP range or domain to remove.")
            return
        removed = False
        for item in selected_items:
            text = item.text().strip()
            if text.startswith("  - "):
                entry = text[4:]
                data = ip_ranges.get(country, {})
                domains = data.get("domains", [])
                ip_ranges_list = data.get("ip_ranges", [])
                if entry in domains:
                    confirm = QMessageBox.question(
                        self, 'Confirm Deletion',
                        f"Are you sure you want to delete the domain '{entry}'?",
                        QMessageBox.Yes | QMessageBox.No,
                        QMessageBox.No
                    )
                    if confirm == QMessageBox.Yes:
                        domains.remove(entry)
                        self.ip_ranges_list.takeItem(self.ip_ranges_list.row(item))
                        log_message(f"Removed domain '{entry}' from {country}.")
                        removed = True
                elif entry in ip_ranges_list:
                    confirm = QMessageBox.question(
                        self, 'Confirm Deletion',
                        f"Are you sure you want to delete the IP range '{entry}'?",
                        QMessageBox.Yes | QMessageBox.No,
                        QMessageBox.No
                    )
                    if confirm == QMessageBox.Yes:
                        ip_ranges_list.remove(entry)
                        self.ip_ranges_list.takeItem(self.ip_ranges_list.row(item))
                        log_message(f"Removed IP range '{entry}' from {country}.")
                        removed = True
        if removed:
            save_ip_ranges(ip_ranges)
            self.show_message("Success", "Selected entry(ies) removed successfully.")
        else:
            self.show_message("Operation Cancelled", "No entries were removed.")
    
    def init_setup(self):
        self.run_in_thread(setup_allowed_ips)
    
    def run_in_thread(self, func, *args, **kwargs):
        self.disable_buttons()
        self.log_area.append("Operation started. Please wait...")
        
        self.thread = QThread()
        self.worker = Worker(func, *args, **kwargs)
        self.worker.moveToThread(self.thread)
        
        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.worker.finished.connect(self.operation_finished)
        
        self.thread.start()
    
    def operation_finished(self):
        self.enable_buttons()
        self.log_area.append("Operation completed.")

class Worker(QObject):
    finished = Signal()
    progress = Signal(str)
    
    def __init__(self, func, *args, **kwargs):
        super().__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs
    
    def run(self):
        try:
            self.func(*self.args, **self.kwargs)
        except Exception as e:
            log_message(f"Error in worker: {e}")
        self.finished.emit()

def main():
    app = QApplication(sys.argv)
    window = FirewallManager()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
