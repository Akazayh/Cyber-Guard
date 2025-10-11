# 🛡 CyberGuard - Comprehensive Security Toolkit

## 📸 Screenshots

### 🖥 Main Menu
![Main](https://github.com/Akazayh/Cyber-Guard/blob/main/CyberGuard/screenshots/main.png)

### 👁 Network Scanner
![Scanner](https://github.com/Akazayh/Cyber-Guard/blob/main/CyberGuard/screenshots/network_scaner.png)

### 🚨 IDS Monitor
![IDS](https://github.com/Akazayh/Cyber-Guard/blob/main/CyberGuard/screenshots/IDS.png)

### 🔍 Log Analyzer
![Analyzer Logs]()

### 🔥 Firewall Manager

![Firewall Manger]()
A powerful, all-in-one cybersecurity tool written in Python that provides network scanning, intrusion detection, log analysis, and firewall management capabilities.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

## 📋 Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Modules](#modules)
- [Requirements](#requirements)
- [Disclaimer](#disclaimer)

## 🚀 Features

### 🔍 Network Scanner (Nmap Integration)
- *19 Different Scan Types* including stealth, aggressive, and vulnerability scans
- *Port Scanning* - Single ports, ranges, and common ports
- *Service Detection* - Version and OS detection
- *Advanced Techniques* - IP spoofing, MAC spoofing, decoy scans
- *Automated Saving* - Results saved to Archives_Nmap/ directory

### 📡 Intrusion Detection System (IDS)
- *Real-time Traffic Monitoring* for both wired and wireless networks
- *Attack Detection*:
  - ARP Spoofing
  - DNS Spoofing
  - SYN/UDP/ICMP Floods
  - Port Scanning
  - Wireless Attacks (Deauth, KRACK, Evil Twin)
- *Live Display* with color-coded alerts
- *Session Logging* in both log and PCAP formats

### 📊 Log Analyzer
- *Comprehensive Analysis* of IDS logs
- *Anomaly Detection* with security issue identification
- *Search Capabilities* with keyword matching
- *Report Generation* for detailed analysis
- *Support for Multiple Log Sources*

### 🔥 Firewall Manager
- *IP Management* - Block/unblock specific IP addresses
- *Port Control* - Manage individual ports and ranges
- *Protocol Filtering* - Control TCP, UDP, and ICMP traffic
- *Rule Persistence* - Save rules across reboots

## 📜 License
This project is licensed under the *MIT License*.

You are *free to use, modify, and share* Cyber Guard in your own projects,
as long as you *credit the original author: Yahya Zhar*.

## 🛠 Installation

### Prerequisites
- Linux OS (Kali Linux recommended)
- Python 3.8 or higher
- Root/sudo privileges

### Quick Setup
```bash
# Clone the repository
git https://github.com/Akazayh/Cyber-Guard.git
cd CyberGuard

# Install dependencies
sudo apt update
sudo apt install iptables beep
pip3 install -r requirements.txt

# Run the tool
sudo python3 main.py
