# 🐍 Python Network Packet Sniffer & Analyzer

## 🚀 Project Overview
A multi-threaded GUI network analysis tool developed in Python. This tool captures real-time network traffic, dissects packet headers (Ethernet, IP, TCP/UDP), and performs **Geo-Location lookup** to visualize the physical destination of traffic.

## 🛠 Features
- **Real-time Packet Capture:** Uses raw sockets via Scapy.
- **Protocol Analysis:** Decodes Ethernet, IP, TCP, UDP, and HTTP (Layer 7).
- **Geo-Location Mapping:** Automatically resolves IP addresses to physical locations (Country/City).
- **Forensic Logging:** Autosaves all sessions to `.pcap` format for Wireshark analysis.
- **Non-Blocking GUI:** Built with Tkinter and Threading to ensure smooth performance.

## 📸 Screenshots
*(Take a screenshot of your tool running and put it here)*

## 💻 How to Run
1. Clone the repository.
2. Install dependencies: `pip install -r requirements.txt`
3. Run with root privileges: `sudo python3 gui_sniffer.py`

## 🔮 Future Roadmap
- [ ] Intrusion Detection System (IDS) for port scan detection.
- [ ] Visual Graphing of traffic volume.
