# python-sniffer/sniffer.py
import scapy.all as scapy
import socketio
import time
import sys
import subprocess
import threading
from collections import defaultdict

# --- Configuration ---
INTERFACE_TO_SNIFF = "wlan0"  # <-- Adjust as needed
NODE_SERVER_URL = 'http://localhost:3000'
PORT_SCAN_THRESHOLD_PORTS = 10
PORT_SCAN_THRESHOLD_SECONDS = 5
port_scan_tracker = defaultdict(list)
port_scan_lock = threading.Lock()

# --- Firewall Management ---
blocked_ips = set()
firewall_lock = threading.Lock()

def run_firewall_command(command_args):
    try:
        subprocess.run(['iptables'] + command_args, check=True, capture_output=True, text=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"[Firewall Error] iptables {' '.join(command_args)} failed: {e.stderr.strip()}")
        return False

def add_firewall_rule(ip_address):
    with firewall_lock:
        if ip_address in blocked_ips:
            return
        if run_firewall_command(['-I', 'INPUT', '1', '-s', ip_address, '-j', 'DROP']):
            blocked_ips.add(ip_address)
            print(f"[Firewall] Blocked {ip_address}")
            sio.emit('ip_blocked', {'ip': ip_address})

def remove_firewall_rule(ip_address):
    with firewall_lock:
        if ip_address not in blocked_ips:
            return
        if run_firewall_command(['-D', 'INPUT', '-s', ip_address, '-j', 'DROP']):
            blocked_ips.remove(ip_address)
            print(f"[Firewall] Unblocked {ip_address}")
            sio.emit('ip_unblocked', {'ip': ip_address})

def cleanup_firewall_rules():
    print("[Firewall] Cleaning up firewall rules...")
    for ip in list(blocked_ips):
        remove_firewall_rule(ip)
    print("[Firewall] Cleanup complete.")

# --- Socket.IO Client ---
sio = socketio.Client()

@sio.event
def connect():
    print("[SocketIO] Connected to Node.js server.")

@sio.event
def disconnect():
    print("[SocketIO] Disconnected from Node.js server.")

@sio.event
def connect_error(data):
    print(f"[SocketIO] Connection error: {data}")

@sio.on('unblock_ip')
def handle_unblock_ip(data):
    ip = data.get('ip')
    if ip:
        remove_firewall_rule(ip)

# --- Packet Analysis ---
def analyze_packet(packet):
    try:
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src

            # Port Scan Detection (SYN packets)
            if packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == 'S':
                dst_port = packet[scapy.TCP].dport
                now = time.time()
                with port_scan_lock:
                    port_scan_tracker[src_ip].append(now)
                    port_scan_tracker[src_ip] = [t for t in port_scan_tracker[src_ip] if now - t <= PORT_SCAN_THRESHOLD_SECONDS]
                    if len(port_scan_tracker[src_ip]) > PORT_SCAN_THRESHOLD_PORTS:
                        alert = {
                            'type': 'Port Scan Detected',
                            'source_ip': src_ip,
                            'target_port': dst_port,
                            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                        }
                        print(f"ALERT: {alert}")
                        sio.emit('suspicious_packet', alert)
                        add_firewall_rule(src_ip)
                        port_scan_tracker[src_ip] = []

            # NULL Scan Detection
            elif packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == 0:
                alert = {
                    'type': 'NULL Scan Detected',
                    'source_ip': src_ip,
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                }
                print(f"ALERT: {alert}")
                sio.emit('suspicious_packet', alert)
                add_firewall_rule(src_ip)

            # Xmas Scan Detection
            elif packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == 'FPU':
                alert = {
                    'type': 'Xmas Scan Detected',
                    'source_ip': src_ip,
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                }
                print(f"ALERT: {alert}")
                sio.emit('suspicious_packet', alert)
                add_firewall_rule(src_ip)

    except Exception as e:
        print(f"[Error] Packet analysis error: {e}")

def start_sniffing():
    print(f"[Sniffer] Starting on {INTERFACE_TO_SNIFF}")
    try:
        sio.connect(NODE_SERVER_URL)
    except Exception as e:
        print(f"[SocketIO] Connection failed: {e}. Running offline.")

    try:
        scapy.sniff(iface=INTERFACE_TO_SNIFF, prn=analyze_packet, store=0)
    except PermissionError:
        print("Run this script with sudo.")
    except KeyboardInterrupt:
        print("Stopping sniffer...")
    finally:
        cleanup_firewall_rules()
        if sio.connected:
            sio.disconnect()
        print("[Sniffer] Shutdown complete.")

if __name__ == "__main__":
    start_sniffing()
