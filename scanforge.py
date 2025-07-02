import argparse
import ipaddress
import random
import socket
from scapy.all import IP, TCP, sr1
from concurrent.futures import ThreadPoolExecutor, as_completed

# Create a TCP SYN scan
def scan_port(ip, port, timeout=1):
    src_port = random.randint(1024, 65535)
    ip_layer = IP(dst=ip)
    tcp_layer = TCP(sport=src_port, dport=port, flags="S")
    packet = ip_layer / tcp_layer

    response = sr1(packet, timeout=timeout, verbose=0)
    if response is None:
        return None

    if response.haslayer(TCP) and response[TCP].flags == 0x12:  # SYN-ACK
        # Send RST to close connection
        rst = IP(dst=ip)/TCP(sport=src_port, dport=port, flags="R")
        sr1(rst, timeout=timeout, verbose=0)
        return port

    return None

# Try to grab banner if possible
def grab_banner(ip, port, timeout=1):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = sock.recv(1024).decode().strip()
            return banner
    except:
        return None

# Parse ports from CLI input
def parse_ports(port_str):
    ports = set()
    for part in port_str.split(","):
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

def scan_host(ip, ports, grab=False):
    open_ports = []

    print(f"\n🔍 Scanning Host: {ip}")
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in ports}

        for future in as_completed(futures):
            port = futures[future]
            result = future.result()
            if result:
                banner = grab_banner(ip, port) if grab else ""
                service = socket.getservbyport(port, "tcp") if port < 1024 else "Unknown"
                print(f"  ✅ Port {port} OPEN ({service}) {'| Banner: ' + banner if banner else ''}")
                open_ports.append(port)

    if not open_ports:
        print("  ❌ No open ports found.")

def main():
    parser = argparse.ArgumentParser(description="Advanced TCP Port Scanner using Scapy")
    parser.add_argument("target", help="Target IP address or CIDR range (e.g., 192.168.1.1 or 10.0.0.0/24)")
    parser.add_argument("-p", "--ports", default="1-1024", help="Ports to scan (e.g., 80,443,21-25)")
    parser.add_argument("-b", "--banner", action="store_true", help="Attempt to grab service banner")
    args = parser.parse_args()

    try:
        ip_list = [str(ip) for ip in ipaddress.ip_network(args.target, strict=False).hosts()]
    except ValueError:
        print("[!] Invalid IP or CIDR range.")
        return

    ports = parse_ports(args.ports)

    for ip in ip_list:
        scan_host(ip, ports, grab=args.banner)

if __name__ == "__main__":
    main()
