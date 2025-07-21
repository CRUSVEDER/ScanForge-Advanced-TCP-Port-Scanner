#!/usr/bin/env python3

import argparse
import ipaddress
import random
import socket
from scapy.all import IP, TCP, sr1
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich import print
import pyfiglet

# Display a banner using rich
result = pyfiglet.figlet_format("CRUS SCANNER", font="slant")
print(f"[bold cyan]{result}[/bold cyan]")

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
        rst = IP(dst=ip) / TCP(sport=src_port, dport=port, flags="R")
        sr1(rst, timeout=timeout, verbose=0)
        return port

    return None

# Try to grab banner if possible
def grab_banner(ip, port, timeout=1):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = sock.recv(1024).decode(errors="ignore").strip()
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
                try:
                    service = socket.getservbyport(port, "tcp")
                except:
                    service = "Unknown"
                print(f"  ✅ Port {port} OPEN ({service}) {'| Banner: ' + banner if banner else ''}")
                open_ports.append(port)

    if not open_ports:
        print("  ❌ No open ports found.")

# Interactive CLI loop
def interactive_shell():
    print("\n[bold yellow]Enter commands like:[/bold yellow]")
    print("  [green]scan 192.168.1.1 -p 80,443 -b[/green]")
    print("  [green]exit[/green] or [green]quit[/green] to leave.\n")

    while True:
        try:
            cmd_input = input("crus> ").strip()
            if cmd_input.lower() in {"exit", "quit"}:
                print("[cyan]Goodbye![/cyan]")
                break
            elif cmd_input.lower() in {"help", "h", "?"}:
                print("Commands:\n  scan <target> [-p ports] [-b]\n  exit\n")
                continue
            elif cmd_input.startswith("scan"):
                import shlex
                parts = shlex.split(cmd_input)[1:]  # skip 'scan'
                parser = argparse.ArgumentParser()
                parser.add_argument("target")
                parser.add_argument("-p", "--ports", default="1-1024")
                parser.add_argument("-b", "--banner", action="store_true")
                try:
                    args = parser.parse_args(parts)
                    try:
                        ip_list = [str(ip) for ip in ipaddress.ip_network(args.target, strict=False).hosts()]
                    except ValueError:
                        print("[red][!] Invalid IP or CIDR range.[/red]")
                        continue

                    ports = parse_ports(args.ports)
                    for ip in ip_list:
                        scan_host(ip, ports, grab=args.banner)

                except SystemExit:
                    print("[red][!] Invalid command or arguments.[/red]")
                    continue
            else:
                print("[red][!] Unknown command. Type 'help' to see usage.[/red]")
        except KeyboardInterrupt:
            print("\n[cyan]Exiting...[/cyan]")
            break

# Main entry
def main():
    interactive_shell()

if __name__ == "__main__":
    main()
