import threading
import tkinter as tk
from tkinter import scrolledtext, font, messagebox
import requests
from scapy.all import *
from scapy.utils import PcapWriter
import time
import os
import psutil
from collections import defaultdict

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Traffic Sniffer v4.0 (IDS + IPS + User Confirmation)")
        self.root.geometry("1300x800")

        # --- CONTROLS SECTION ---
        control_frame = tk.Frame(root)
        control_frame.pack(pady=10)

        # Filter
        tk.Label(control_frame, text="BPF Filter:").pack(side=tk.LEFT, padx=5)
        self.filter_entry = tk.Entry(control_frame, width=20)
        self.filter_entry.pack(side=tk.LEFT, padx=5)
        self.filter_entry.insert(0, "tcp or udp") 

        # Buttons
        self.start_btn = tk.Button(control_frame, text="Start System", command=self.start_sniffing, bg="#4CAF50", fg="white", width=12)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn = tk.Button(control_frame, text="Stop", command=self.stop_sniffing, bg="#f44336", fg="white", width=12, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        # Toggles
        self.geo_var = tk.BooleanVar(value=True)
        tk.Checkbutton(control_frame, text="Geo-IP", variable=self.geo_var).pack(side=tk.LEFT, padx=5)

        # UPDATED: Changed text to reflect new behavior
        self.block_var = tk.BooleanVar(value=False)
        self.block_chk = tk.Checkbutton(control_frame, text="⛔ IPS (Ask to Block)", variable=self.block_var, fg="red", font=("Arial", 10, "bold"))
        self.block_chk.pack(side=tk.LEFT, padx=10)

        # --- OUTPUT SECTION ---
        self.custom_font = font.Font(family="Courier", size=10)
        self.log_area = scrolledtext.ScrolledText(root, width=140, height=35, font=self.custom_font)
        self.log_area.pack(padx=10, pady=10)

        # Colors
        self.log_area.tag_config("alert", foreground="red", font=(self.custom_font, 10, "bold"))
        self.log_area.tag_config("block", foreground="white", background="red", font=(self.custom_font, 10, "bold"))
        self.log_area.tag_config("process", foreground="green", font=(self.custom_font, 10, "bold"))
        self.log_area.tag_config("data", foreground="blue")
        self.log_area.tag_config("normal", foreground="black")

        # --- VARIABLES ---
        self.sniffing = False
        self.pcap_writer = None
        self.sniffer_thread = None
        self.ip_cache = {} 
        self.process_cache = {} 
        self.blocked_ips = set()
        self.prompted_ips = set() # NEW: Remembers IPs we already asked about

        # IDS Thresholds
        self.scan_tracker = defaultdict(lambda: {'ports': set(), 'last_time': 0})
        self.SCAN_THRESHOLD = 15
        self.TIME_WINDOW = 10
        self.suspicious_keywords = ["password", "login", "admin", "root", "script", "union select", "eval(", "alert("]

    def start_sniffing(self):
        user_filter = self.filter_entry.get()
        self.pcap_filename = f"capture_{int(time.time())}.pcap"
        self.pcap_writer = PcapWriter(self.pcap_filename, append=True, sync=True)
        
        self.sniffing = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.log_area.delete(1.0, tk.END)
        self.log_area.insert(tk.END, f"[*] SYSTEM STARTED... Logging to: {self.pcap_filename}\n", "normal")
        
        self.sniffer_thread = threading.Thread(target=self.run_sniffer, args=(user_filter,))
        self.sniffer_thread.daemon = True 
        self.sniffer_thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        self.log_area.insert(tk.END, "\n[*] SYSTEM STOPPED.\n", "normal")
        self.log_area.see(tk.END)
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

    def run_sniffer(self, user_filter):
        try:
            sniff(filter=user_filter, prn=self.process_packet, stop_filter=self.should_stop, store=False)
        except Exception as e:
            self.update_log(f"\n[!] Error: {e}\n", "alert")
            self.stop_sniffing()

    def should_stop(self, packet):
        return not self.sniffing

    def get_process_name(self, port):
        if port in self.process_cache: return self.process_cache[port]
        try:
            for conn in psutil.net_connections():
                if conn.laddr.port == port:
                    if conn.pid:
                        name = psutil.Process(conn.pid).name()
                        self.process_cache[port] = name 
                        return name
        except: pass
        return None

    # --- NEW: THREAD-SAFE POPUP ---
    def show_block_prompt(self, ip, reason):
        # We assume 'Yes' to block
        if messagebox.askyesno("IPS Alert", f"⚠️ THREAT DETECTED!\n\nSource: {ip}\nReason: {reason}\n\nDo you want to BLOCK this IP on the Firewall?"):
            self.block_ip(ip)
        else:
            self.update_log(f"\n[*] User chose NOT to block {ip}.\n", "normal")

    def trigger_block_prompt(self, ip, reason):
        # Only ask if enabled, not blocked yet, and haven't asked recently
        if self.block_var.get() and ip not in self.blocked_ips and ip not in self.prompted_ips:
            # Mark as prompted so we don't spam 100 popups for 100 packets
            self.prompted_ips.add(ip)
            # Schedule the popup on the MAIN THREAD to avoid crashing
            self.root.after(0, lambda: self.show_block_prompt(ip, reason))

    def block_ip(self, ip):
        if ip in self.blocked_ips or ip.startswith("127.") or ip.startswith("192.168."): return
        try:
            cmd = f"iptables -A INPUT -s {ip} -j DROP"
            os.system(f"sudo {cmd}")
            self.blocked_ips.add(ip)
            self.update_log(f"\n[⛔] IPS ACTION: BLOCKED IP {ip}!\n", "block")
        except: pass

    def get_location(self, ip):
        if ip in self.ip_cache: return self.ip_cache[ip]
        if ip.startswith("192.168.") or ip.startswith("10."): return "[Local]"
        if self.geo_var.get():
            try:
                response = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
                data = response.json()
                if data['status'] == 'success':
                    loc = f"[{data['countryCode']}]"
                    self.ip_cache[ip] = loc
                    return loc
            except: pass
        return ""

    def check_port_scan(self, src_ip, dst_port):
        tracker = self.scan_tracker[src_ip]
        if time.time() - tracker['last_time'] > self.TIME_WINDOW:
            tracker['ports'].clear()
        tracker['last_time'] = time.time()
        tracker['ports'].add(dst_port)
        return len(tracker['ports']) > self.SCAN_THRESHOLD

    def process_packet(self, packet):
        if self.pcap_writer: self.pcap_writer.write(packet)
        pkt_summary = ""
        tag = "normal"
        
        if packet.haslayer(IP):
            ip = packet[IP]
            src_ip = ip.src
            dst_ip = ip.dst
            
            # --- IDS CHECK: PORT SCAN ---
            if packet.haslayer(TCP):
                if self.check_port_scan(src_ip, packet[TCP].dport):
                    alert_msg = f"\n[!!!] ALERT: PORT SCAN FROM {src_ip}"
                    self.update_log(alert_msg, "alert")
                    # Trigger the Popup Prompt
                    self.trigger_block_prompt(src_ip, "Port Scan Detected")

            # --- IDS CHECK: PAYLOAD ---
            if packet.haslayer(Raw):
                try:
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                    for k in self.suspicious_keywords:
                        if k in payload.lower():
                            self.update_log(f"\n[!!!] MALICIOUS: '{k}' FROM {src_ip}", "alert")
                            # Trigger the Popup Prompt
                            self.trigger_block_prompt(src_ip, f"Malicious Keyword: {k}")
                            break
                    if "GET " in payload or "POST " in payload:
                        pkt_summary += f"\n    [>> DATA] {payload[:80].replace('\n', ' ')}..."
                        tag = "data"
                except: pass

            # --- DISPLAY ---
            if src_ip not in self.blocked_ips:
                dst_loc = self.get_location(dst_ip)
                pkt_summary = f"[IP] {src_ip} -> {dst_ip} {dst_loc}" + pkt_summary
                
                proc_name = ""
                if packet.haslayer(TCP):
                    app = self.get_process_name(packet[TCP].sport)
                    if app: proc_name = f" [{app}]"
                    pkt_summary += f" | [TCP] {packet[TCP].sport} -> {packet[TCP].dport}"
                    
                elif packet.haslayer(UDP):
                    app = self.get_process_name(packet[UDP].sport)
                    if app: proc_name = f" [{app}]"
                    pkt_summary += f" | [UDP] {packet[UDP].sport} -> {packet[UDP].dport}"

                self.update_log(pkt_summary, tag)
                if proc_name:
                    self.update_log(proc_name + "\n", "process")
                else:
                    self.update_log("\n", "normal")

    def update_log(self, text, tag):
        self.log_area.insert(tk.END, text, tag)
        self.log_area.see(tk.END)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Run with sudo!")
        exit()
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
