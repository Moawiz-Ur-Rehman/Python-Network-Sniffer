# 🛡️ Python Network Sentinel (Sniffer, IDS & IPS)

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Security](https://img.shields.io/badge/Security-IDS%2FIPS-red?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey?style=for-the-badge&logo=linux)

## 🚀 Project Overview
**Python Network Sentinel** is a comprehensive cybersecurity tool designed to bridge the gap between passive network monitoring and active defense. 

Unlike standard sniffers that simply "watch" traffic, this application acts as a **Host-Based Intrusion Prevention System (HIPS)**. It monitors network packets in real-time, identifies the specific application responsible for the traffic (Process Fingerprinting), detects malicious patterns, and empowers the user to **block threats** instantly via the Linux Kernel Firewall (`iptables`).

## ⚡ Key Features

### 1. 🕵️ Deep Packet Inspection (DPI)
- Decodes **Ethernet, IP, TCP, UDP, and HTTP** headers in real-time.
- Extracts and displays unencrypted **HTTP Payloads** (e.g., POST data, passwords).
- **Geo-Location:** Automatically maps Destination IPs to physical countries (e.g., `[US]`, `[DE]`, `[CN]`) using the IP-API.

### 2. 🧠 Process Fingerprinting
- **"Who is talking?"** The tool queries the OS kernel to identify exactly which application is generating traffic.
- **Visual Feedback:** Trusted processes (like `firefox` or `discord`) appear in **GREEN** next to the packet data.

### 3. 🚨 Intrusion Detection System (IDS)
- **Port Scan Detection:** Uses heuristic analysis to detect if a single IP is probing multiple ports rapidly.
- **Signature Matching:** Scans packet payloads for malicious keywords (e.g., `union select`, `alert(`, `/etc/passwd`).
- **Alerting:** Suspicious packets are highlighted in **RED** in the live log.

### 4. ⛔ Active Defense (IPS)
- **"Human-in-the-Loop" Security:** When a high-severity threat is detected, the system triggers a **Popup Alert**.
- **Firewall Integration:** If the user approves, the tool dynamically executes an `iptables` command to **DROP** all future traffic from the attacker's IP address.

### 5. 💾 Forensic Logging
- Automatically saves all captured traffic to standard `.pcap` files.
- Files can be opened in **Wireshark** for deep-dive forensic analysis later.

---

## 📸 Screenshots

### 1. The Dashboard (Process Detection & Geo-Location)
<img width="1140" height="429" alt="Screenshot 2026-01-04 213536" src="https://github.com/user-attachments/assets/e6447283-d7c6-4093-a34a-fcc5a8d1be23" />


### 2. Active Defense (IPS Popup)
<img width="1233" height="444" alt="Screenshot 2026-01-04 214150" src="https://github.com/user-attachments/assets/a7a8d9d6-d1ae-4bb4-a44b-f87ccba1acbc" />

---

## 💻 Installation & Usage

### Prerequisites
This tool is designed for **Linux** (Kali, Ubuntu, Debian) as it relies on `iptables` for blocking and raw sockets for sniffing.

1. **Clone the Repository**
   ```bash
   git clone [https://github.com/Moawiz-Ur-Rehman/Python-Network-Sniffer.git](https://github.com/Moawiz-Ur-Rehman/Python-Network-Sniffer.git)
   cd Python-Network-Sniffer
⚠️ Disclaimer
This tool interacts with the operating system's firewall (iptables). While safety checks are included to prevent blocking Local IPs (127.0.0.1, 192.168.x.x), please use caution on production machines to avoid accidental network lockouts.
