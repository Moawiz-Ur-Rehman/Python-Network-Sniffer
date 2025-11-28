import threading
import tkinter as tk
from tkinter import scrolledtext
import requests  # NEW: For Geo-Location
from scapy.all import *
from scapy.utils import PcapWriter
import time
import os

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Traffic Sniffer v2 (with Geo-Location)")
        self.root.geometry("1000x700") # Made window slightly wider

        # --- CONTROLS SECTION ---
        control_frame = tk.Frame(root)
        control_frame.pack(pady=10)

        # Filter Label
        tk.Label(control_frame, text="BPF Filter:").pack(side=tk.LEFT, padx=5)
        self.filter_entry = tk.Entry(control_frame, width=30)
        self.filter_entry.pack(side=tk.LEFT, padx=5)
        self.filter_entry.insert(0, "tcp") 

        # Start Button
        self.start_btn = tk.Button(control_frame, text="Start Sniffing", command=self.start_sniffing, bg="#4CAF50", fg="white", width=15)
        self.start_btn.pack(side=tk.LEFT, padx=10)

        # Stop Button
        self.stop_btn = tk.Button(control_frame, text="Stop Sniffing", command=self.stop_sniffing, bg="#f44336", fg="white", width=15, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=10)

        # Toggle for Geo-Location (Optional, to save API usage)
        self.geo_var = tk.BooleanVar()
        self.geo_var.set(True) # Default is ON
        self.geo_chk = tk.Checkbutton(control_frame, text="Enable Geo-Location", variable=self.geo_var)
        self.geo_chk.pack(side=tk.LEFT, padx=10)

        # --- OUTPUT SECTION ---
        self.log_area = scrolledtext.ScrolledText(root, width=110, height=35)
        self.log_area.pack(padx=10, pady=10)

        # --- VARIABLES ---
        self.sniffing = False
        self.pcap_writer = None
        self.sniffer_thread = None
        self.pcap_filename = ""
        
        # CACHE: To store IP locations so we don't query the API 100 times for the same IP
        self.ip_cache = {} 

    def start_sniffing(self):
        user_filter = self.filter_entry.get()
        self.pcap_filename = f"capture_{int(time.time())}.pcap"
        self.pcap_writer = PcapWriter(self.pcap_filename, append=True, sync=True)
        
        self.sniffing = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        
        self.log_area.delete(1.0, tk.END)
        self.log_area.insert(tk.END, f"[*] Started... Saving to: {self.pcap_filename}\n")
        
        self.sniffer_thread = threading.Thread(target=self.run_sniffer, args=(user_filter,))
        self.sniffer_thread.daemon = True 
        self.sniffer_thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        self.log_area.insert(tk.END, "\n[*] Stopping sniffer...\n")
        self.log_area.see(tk.END)
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

    def run_sniffer(self, user_filter):
        try:
            if user_filter:
                sniff(filter=user_filter, prn=self.process_packet, stop_filter=self.should_stop, store=False)
            else:
                sniff(prn=self.process_packet, stop_filter=self.should_stop, store=False)
        except Exception as e:
            self.update_log(f"\n[!] Error: {e}\n")
            self.stop_sniffing()

    def should_stop(self, packet):
        return not self.sniffing

    def get_location(self, ip):
        # 1. Check if we already looked this up
        if ip in self.ip_cache:
            return self.ip_cache[ip]
        
        # 2. Check for Private IPs (LAN) - Don't lookup local devices
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("127."):
            return "[Local]"

        # 3. Query the API (Only if Geo checkbox is Checked)
        if self.geo_var.get():
            try:
                # We use ip-api.com (Free, no key required for low volume)
                response = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
                data = response.json()
                if data['status'] == 'success':
                    country = data.get('countryCode', '??')
                    city = data.get('city', 'Unknown')
                    isp = data.get('org', 'Unknown ISP')
                    location_str = f"[{country}-{city}]"
                    
                    # Save to cache
                    self.ip_cache[ip] = location_str
                    return location_str
            except:
                return "[Geo-Error]"
        
        return ""

    def process_packet(self, packet):
        if self.pcap_writer:
            self.pcap_writer.write(packet)
            
        pkt_summary = ""
        
        if packet.haslayer(IP):
            ip = packet[IP]
            
            # --- NEW: Get Geo Location ---
            # We look up the Destination IP to see where traffic is GOING
            dst_loc = self.get_location(ip.dst)
            
            pkt_summary = f"[IP] {ip.src} -> {ip.dst} {dst_loc}"
            
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                pkt_summary += f" | [TCP] {tcp.sport} -> {tcp.dport}"
                if tcp.flags & 0x02: pkt_summary += " [SYN]" 
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                pkt_summary += f" | [UDP] {udp.sport} -> {udp.dport}"

            if packet.haslayer(Raw):
                try:
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                    if "GET " in payload or "POST " in payload or "HTTP" in payload:
                        clean_payload = payload.replace('\r', '').replace('\n', ' ')
                        pkt_summary += f"\n    [>> DATA] {clean_payload[:80]}..." 
                except:
                    pass
        
        if pkt_summary:
            self.update_log(pkt_summary + "\n")

    def update_log(self, text):
        self.log_area.insert(tk.END, text)
        self.log_area.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
