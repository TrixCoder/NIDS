# send_test_packets.py
import scapy.all as scapy
import time
import sys
import random

# --- Configuration ---
# !! REPLACE WITH THE ACTUAL IP ADDRESS of the machine running sniffer.py !!
TARGET_IP = "192.168.1.10"
# Use a non-standard source port for testing
SOURCE_PORT = random.randint(1024, 65530)

# --- Packet Crafting Functions ---

def send_port_scan(target_ip, count=15, delay=0.1):
    """Simulates a simple TCP SYN port scan."""
    print(f"[*] Sending SYN Port Scan to {target_ip} (Ports 1-{count})...")
    # Send SYN packets to a range of destination ports
    for port in range(1, count + 1):
        # Craft the IP and TCP layers
        ip_layer = scapy.IP(dst=target_ip)
        # SYN flag is set by default if no other flags specified with seq=0
        tcp_layer = scapy.TCP(sport=SOURCE_PORT, dport=port, flags='S')
        packet = ip_layer / tcp_layer
        scapy.send(packet, verbose=0) # verbose=0 suppresses Scapy's output
        print(f"    Sent SYN to port {port}")
        time.sleep(delay)
    print("[*] Port Scan simulation finished.")

def send_null_scan(target_ip, target_port=80):
    """Sends a TCP packet with no flags set."""
    print(f"[*] Sending NULL Scan to {target_ip}:{target_port}...")
    ip_layer = scapy.IP(dst=target_ip)
    # Explicitly set flags to 0 for a NULL scan
    tcp_layer = scapy.TCP(sport=SOURCE_PORT, dport=target_port, flags=0)
    packet = ip_layer / tcp_layer
    scapy.send(packet, verbose=0)
    print("[*] NULL Scan packet sent.")

def send_xmas_scan(target_ip, target_port=80):
    """Sends a TCP packet with FIN, PSH, URG flags set."""
    print(f"[*] Sending Xmas Scan to {target_ip}:{target_port}...")
    ip_layer = scapy.IP(dst=target_ip)
    # Set the FIN, PSH, and URG flags ('FPU')
    tcp_layer = scapy.TCP(sport=SOURCE_PORT, dport=target_port, flags='FPU')
    packet = ip_layer / tcp_layer
    scapy.send(packet, verbose=0)
    print("[*] Xmas Scan packet sent.")

# --- Main Execution ---
if __name__ == "__main__":
    if len(sys.argv) > 1:
        TARGET_IP = sys.argv[1]
        print(f"[i] Using target IP from command line: {TARGET_IP}")
    else:
         print(f"[i] Using default target IP: {TARGET_IP}. Provide IP as argument if needed.")


    print("\n--- Starting NIDS Test Traffic Generation ---")

    # 1. Send NULL Scan
    send_null_scan(TARGET_IP, target_port=443) # Target common port
    time.sleep(1) # Pause between tests

    # 2. Send Xmas Scan
    send_xmas_scan(TARGET_IP, target_port=22) # Target another common port
    time.sleep(1) # Pause between tests

    # 3. Send Port Scan
    # Adjust count/delay to ensure it triggers your sniffer's threshold
    # (Default sniffer: >10 ports within 5 seconds)
    send_port_scan(TARGET_IP, count=15, delay=0.1)

    print("\n--- Test Traffic Generation Complete ---")