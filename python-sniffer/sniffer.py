# python-sniffer/sniffer.py
import scapy.all as scapy
import socketio
import time
import sys
import subprocess
import threading
import json
import os
from collections import defaultdict
from datetime import datetime

# --- Configuration ---
INTERFACE_TO_SNIFF = "wlan0"  # <-- Adjust as needed
NODE_SERVER_URL = 'http://localhost:3000'
PORT_SCAN_THRESHOLD_PORTS = 10
PORT_SCAN_THRESHOLD_SECONDS = 5
BLOCKED_IPS_FILE = 'blocked_ips.json'
ALERT_LOGS_FILE = 'alert_logs.json'  # New file for storing alerts
SUSPICIOUS_PCAP = '../suspicious.pcap'  # Path to suspicious PCAP file
FINGERPRINTS_FILE = 'attack_fingerprints.json'

# Data structures
port_scan_tracker = defaultdict(list)
port_scan_lock = threading.Lock()
fingerprints = {}  # Will store attack patterns from PCAP analysis

# --- Persistent Storage ---
def load_blocked_ips():
    """Load blocked IPs from file"""
    if os.path.exists(BLOCKED_IPS_FILE):
        try:
            with open(BLOCKED_IPS_FILE, 'r') as f:
                data = json.load(f)
                return set(data.get('blocked_ips', []))
        except (json.JSONDecodeError, IOError) as e:
            print(f"[Error] Failed to load blocked IPs: {e}")
    return set()

def save_blocked_ips(blocked_ips):
    """Save blocked IPs to file"""
    try:
        with open(BLOCKED_IPS_FILE, 'w') as f:
            json.dump({'blocked_ips': list(blocked_ips)}, f)
    except IOError as e:
        print(f"[Error] Failed to save blocked IPs: {e}")

def save_alert_log(alert_data):
    """Save alert to log file"""
    try:
        alerts = []
        if os.path.exists(ALERT_LOGS_FILE):
            with open(ALERT_LOGS_FILE, 'r') as f:
                alerts = json.load(f)
        
        alerts.append(alert_data)
        
        # Keep only the last 1000 alerts to prevent file from growing too large
        if len(alerts) > 1000:
            alerts = alerts[-1000:]
            
        with open(ALERT_LOGS_FILE, 'w') as f:
            json.dump(alerts, f, indent=2)
    except Exception as e:
        print(f"[Error] Failed to save alert log: {e}")

# --- Firewall Management ---
blocked_ips = load_blocked_ips()
firewall_lock = threading.Lock()

def run_firewall_command(command_args):
    """Execute an iptables command"""
    try:
        result = subprocess.run(['iptables'] + command_args, check=True, capture_output=True, text=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"[Firewall Error] iptables {' '.join(command_args)} failed: {e.stderr.strip()}")
        return False

def check_if_ip_is_blocked(ip_address):
    """Check if an IP is already blocked in iptables"""
    try:
        result = subprocess.run(
            ['iptables', '-C', 'INPUT', '-s', ip_address, '-j', 'DROP'],
            capture_output=True, text=True
        )
        # Return code 0 means the rule exists
        return result.returncode == 0
    except Exception as e:
        print(f"[Firewall Error] Failed to check if IP is blocked: {e}")
        return False

def add_firewall_rule(ip_address):
    """Block an IP address using iptables"""
    with firewall_lock:
        if ip_address in blocked_ips:
            # IP is already in our list, check if it's actually in the firewall too
            if not check_if_ip_is_blocked(ip_address):
                # IP is in our list but not in firewall, add it
                if run_firewall_command(['-I', 'INPUT', '1', '-s', ip_address, '-j', 'DROP']):
                    print(f"[Firewall] Re-blocked {ip_address}")
                    sio.emit('ip_blocked', {'ip': ip_address})
            return
        
        # New IP to block
        if run_firewall_command(['-I', 'INPUT', '1', '-s', ip_address, '-j', 'DROP']):
            blocked_ips.add(ip_address)
            save_blocked_ips(blocked_ips)
            print(f"[Firewall] Blocked {ip_address}")
            sio.emit('ip_blocked', {'ip': ip_address})

def remove_firewall_rule(ip_address):
    print("running remove_firewall_rule")
    """Unblock an IP address using iptables"""
    with firewall_lock:
        if ip_address not in blocked_ips:
            return
        
        # Check all instances of this rule and remove them
        while check_if_ip_is_blocked(ip_address):
            if run_firewall_command(['-D', 'INPUT', '-s', ip_address, '-j', 'DROP']):
                print(f"[Firewall] Removed a rule for {ip_address}")
            else:
                break
                
        blocked_ips.remove(ip_address)
        save_blocked_ips(blocked_ips)
        print(f"[Firewall] Unblocked {ip_address}")
        sio.emit('ip_unblocked', {'ip': ip_address})

def restore_firewall_rules():
    """Ensure all saved blocked IPs are actually in the firewall"""
    print("[Firewall] Restoring firewall rules from saved state...")
    for ip in blocked_ips:
        if not check_if_ip_is_blocked(ip):
            print(f"[Firewall] Restoring block for {ip}")
            run_firewall_command(['-I', 'INPUT', '1', '-s', ip, '-j', 'DROP'])
    print("[Firewall] Firewall rules restored.")

def cleanup_firewall_rules():
    """Clean up firewall rules when exiting"""
    print("[Firewall] Cleaning up firewall rules...")
    # Only remove rules if requested - comment this out to keep blocks after restart
    # for ip in list(blocked_ips):
    #    remove_firewall_rule(ip)
    print("[Firewall] Cleanup complete.")

# --- PCAP Analysis for Training ---
def extract_fingerprints_from_pcap():
    """Analyze PCAP file to extract attack signatures/fingerprints"""
    if not os.path.exists(SUSPICIOUS_PCAP):
        print(f"[Warning] PCAP file {SUSPICIOUS_PCAP} not found. Skipping training.")
        return {}
    
    print(f"[Training] Analyzing {SUSPICIOUS_PCAP} for attack patterns...")
    attack_signatures = {
        'null_scan': [],
        'xmas_scan': [],
        'port_scan': []
    }
    
    try:
        packets = scapy.rdpcap(SUSPICIOUS_PCAP)
        
        # Extract specific packet characteristics to identify attacks
        for packet in packets:
            if packet.haslayer(scapy.TCP):
                tcp = packet[scapy.TCP]
                
                # NULL scan (no flags)
                if tcp.flags == 0:
                    src_ip = packet[scapy.IP].src if packet.haslayer(scapy.IP) else None
                    if src_ip:
                        attack_signatures['null_scan'].append(src_ip)
                
                # XMAS scan (FIN, PSH, URG flags)
                elif tcp.flags == 'FPU':
                    src_ip = packet[scapy.IP].src if packet.haslayer(scapy.IP) else None
                    if src_ip:
                        attack_signatures['xmas_scan'].append(src_ip)
                
                # For port scans, we'll collect based on suspicious patterns
                elif tcp.flags == 'S':  # SYN packets
                    src_ip = packet[scapy.IP].src if packet.haslayer(scapy.IP) else None
                    if src_ip:
                        attack_signatures['port_scan'].append(src_ip)
        
        # Save the fingerprints
        with open(FINGERPRINTS_FILE, 'w') as f:
            json.dump(attack_signatures, f)
            
        # Remove duplicates for in-memory use
        for key in attack_signatures:
            attack_signatures[key] = list(set(attack_signatures[key]))
            
        print(f"[Training] Extracted {len(attack_signatures['null_scan'])} NULL scan IPs, "
              f"{len(attack_signatures['xmas_scan'])} XMAS scan IPs, and "
              f"{len(attack_signatures['port_scan'])} port scan IPs.")
        
        return attack_signatures
    
    except Exception as e:
        print(f"[Error] Failed to analyze PCAP: {e}")
        return {}

def load_fingerprints():
    """Load attack fingerprints from file or create from PCAP"""
    if os.path.exists(FINGERPRINTS_FILE):
        try:
            with open(FINGERPRINTS_FILE, 'r') as f:
                return json.load(f)
        except:
            pass
    
    # If loading fails or file doesn't exist, extract from PCAP
    return extract_fingerprints_from_pcap()

# --- Socket.IO Client ---
sio = socketio.Client()

@sio.event
def connect():
    print("[SocketIO] Connected to Node.js server.")
    # When connecting, send current list of blocked IPs
    for ip in blocked_ips:
        sio.emit('ip_blocked', {'ip': ip})

@sio.event
def disconnect():
    print("[SocketIO] Disconnected from Node.js server.")

@sio.event
def connect_error(data):
    print(f"[SocketIO] Connection error: {data}")

@sio.on('ip_unblocked')
def handle_ip_unblocked(data):
    ip = data.get('ip')
    if ip:
        remove_firewall_rule(ip)

@sio.on('block_ip')
def handle_block_ip(data):
    ip = data.get('ip')
    if ip:
        add_firewall_rule(ip)

# --- Packet Analysis ---
def create_alert(alert_type, src_ip, target_port=None, details=None):
    """Create a standardized alert object"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    alert = {
        'type': alert_type,
        'source_ip': src_ip,
        'timestamp': timestamp
    }
    
    if target_port:
        alert['target_port'] = target_port
    if details:
        alert['details'] = details
    
    return alert

def analyze_packet(packet):
    """Analyze a packet for suspicious behavior"""
    try:
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            
            # Skip processing packets from already blocked IPs
            if src_ip in blocked_ips:
                return
            
            # Check if the source IP is in our fingerprints
            for attack_type, ips in fingerprints.items():
                if src_ip in ips:
                    # This IP was previously identified in a PCAP file
                    alert = create_alert(
                        f'Known {attack_type.replace("_", " ").title()} Source',
                        src_ip,
                        details='Match found in training data'
                    )
                    print(f"ALERT: {alert}")
                    save_alert_log(alert)
                    sio.emit('suspicious_packet', alert)
                    add_firewall_rule(src_ip)
                    return

            # Port Scan Detection (SYN packets)
            if packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == 'S':
                dst_port = packet[scapy.TCP].dport
                now = time.time()
                with port_scan_lock:
                    port_scan_tracker[src_ip].append(now)
                    port_scan_tracker[src_ip] = [t for t in port_scan_tracker[src_ip] if now - t <= PORT_SCAN_THRESHOLD_SECONDS]
                    if len(port_scan_tracker[src_ip]) > PORT_SCAN_THRESHOLD_PORTS:
                        alert = create_alert('Port Scan Detected', src_ip, dst_port)
                        print(f"ALERT: {alert}")
                        save_alert_log(alert)
                        sio.emit('suspicious_packet', alert)
                        add_firewall_rule(src_ip)
                        port_scan_tracker[src_ip] = []

            # NULL Scan Detection
            elif packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == 0:
                alert = create_alert('NULL Scan Detected', src_ip, packet[scapy.TCP].dport)
                print(f"ALERT: {alert}")
                save_alert_log(alert)
                sio.emit('suspicious_packet', alert)
                add_firewall_rule(src_ip)

            # Xmas Scan Detection
            elif packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == 'FPU':
                alert = create_alert('Xmas Scan Detected', src_ip, packet[scapy.TCP].dport)
                print(f"ALERT: {alert}")
                save_alert_log(alert)
                sio.emit('suspicious_packet', alert)
                add_firewall_rule(src_ip)

    except Exception as e:
        print(f"[Error] Packet analysis error: {e}")

def start_sniffing():
    """Start sniffing packets on the network"""
    global fingerprints
    
    print(f"[Sniffer] Starting on {INTERFACE_TO_SNIFF}")
    
    # Load attack fingerprints from PCAP or cached file
    fingerprints = load_fingerprints()
    print(f"[Sniffer] Loaded fingerprints for detection")
    
    # Restore saved firewall rules
    restore_firewall_rules()
    
    # Connect to the Node.js server
    try:
        sio.connect(NODE_SERVER_URL)
    except Exception as e:
        print(f"[SocketIO] Connection failed: {e}. Running offline.")

    try:
        # Start packet capture
        print("[Sniffer] Starting packet capture...")
        scapy.sniff(iface=INTERFACE_TO_SNIFF, prn=analyze_packet, store=0)
    except PermissionError:
        print("Run this script with sudo.")
    except KeyboardInterrupt:
        print("Stopping sniffer...")
    finally:
        # Save blocked IPs before exiting
        save_blocked_ips(blocked_ips)
        cleanup_firewall_rules()
        if sio.connected:
            sio.disconnect()
        print("[Sniffer] Shutdown complete.")

if __name__ == "__main__":
    start_sniffing()