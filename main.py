#scapy----------------------
from scapy.all import ARP, Ether, srp
from scapy.all import IP, TCP, sr1, send, Raw
#Rich------------------------
from rich.console import Console
from rich.prompt import Prompt
from rich.prompt import IntPrompt
from rich.table import Table
from rich.style import Style
from rich.progress import track
from rich.progress import Progress
from rich.panel import Panel
from rich.console import Console, Group
# other-------------------------------
import re
import ssl
import time
import requests
import socket 
from datetime import datetime
import sys
#Initial panel---------------------
panel1 = Panel("[bold blue]---NetTool Script---[/]\n[red][1]network scan\n[2]open ports scan\n[3]web server type finder\n[4]mini traceroute (:\n[5]exit",title="services list",subtitle="1972Cyrus",title_align='right',subtitle_align='left')

console = Console()
console.print(panel1)

#main code-----------------
def mainloop():
    while True:
#start and services list---
        command = Prompt.ask('[?]:(just number) ' ,choices=["1", "2", "3", "4","5"])

#network scanner------------------------------------------------------------------------
        # Initialize console and table
        console = Console()
        table1 = Table(show_header=True, header_style="bold magenta")
        table1.add_column("IP", style="dim", width=12)
        table1.add_column("MAC Address")
    
        if command == '1':
            ip = input('Enter--> IP/subnet:')  
            arp_request = ARP(pdst=ip)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp_request
            result = srp(packet, timeout=3, verbose=0)[0]
            
            clients = [] 
            
            for sent, received in result:
                clients.append({'ip': received.psrc, 'mac': received.hwsrc})

            table1 = Table(show_header=True, header_style="bold magenta")
            table1.add_column("IP", style="dim", width=12)
            table1.add_column("MAC Address")

            for client in clients:
                table1.add_row(client['ip'], client['mac'])

            console.print(table1)
# port-scaning-----------------------------------------------------------------------
        elif command == '2':

            def syn_scan(target, port):
                pkt = IP(dst=target)/TCP(dport=port, flags='S')
                resp = sr1(pkt, timeout=1, verbose=0)
                if resp is None:
                    return False
                if resp.haslayer(TCP):
                    if resp.getlayer(TCP).flags == 0x12:
                        rst_pkt = IP(dst=target)/TCP(dport=port, flags='R')
                        sr1(rst_pkt, timeout=1, verbose=0)
                        return True
                return False

            def main():
                target = Prompt.ask("Enter Target IP or domain")
                while True:
                    port_start = IntPrompt.ask("Enter port range start (1-65535)")
                    port_end = IntPrompt.ask("Enter port range end (1-65535)")
                    if 1 <= port_start <= 65535 and 1 <= port_end <= 65535 and port_start <= port_end:
                        break
                    console.print("[red]Invalid port range! Try again.[/red]")

                console.print(f"Scanning target: [bold]{target}[/bold]")
                try:
                    for port in track(range(port_start, port_end + 1), description="Scanning ports..."):
                        if syn_scan(target, port):
                            console.print(f"[green]Port {port} is open[/green]")
                except KeyboardInterrupt:
                    console.print("\n[bold red]Scan aborted by user![/bold red]")
                    sys.exit()

            if __name__ == "__main__":
                main()
#web server type finder-------------------------------------------------------------------
        elif command == '3':
            def check_port(ip, port, timeout=2):
                try:
                    sock = socket.create_connection((ip, port), timeout=timeout)
                    sock.close()
                    return True
                except:
                    return False

            def get_http_headers(ip, port=80, use_https=False):
                try:
                    sock = socket.create_connection((ip, port), timeout=3)
                    if use_https:
                        context = ssl.create_default_context()
                        sock = context.wrap_socket(sock, server_hostname=ip)
                    
                    http_request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                    sock.sendall(http_request.encode())
        
                    response = b""
                    while True:
                        data = sock.recv(4096)
                        if not data:
                            break
                        response += data
                    sock.close()
        
                    return response.decode(errors="ignore")
                except Exception as e:
                    return None

            def extract_server_type(http_response):
                if http_response:
                    match = re.search(r"Server:\s*([^\r\n]+)", http_response, re.IGNORECASE)
                    if match:
                        return match.group(1).strip()
                return "Unknown"

            def main():
                console = Console()
                target = console.input("[bold cyan]Enter target domain or IP:[/bold cyan] ").strip()
                
                try:
                    ip = socket.gethostbyname(target)
                except Exception as e:
                    console.print(f"[bold red]Error resolving hostname:[/bold red] {e}")
                    return
    
                console.print(f"[yellow]Checking open ports on {ip}...[/yellow]")
                
                server_type = "Unknown"
                if check_port(ip, 80):
                    console.print("[green]Port 80 open → HTTP[/green]")
                    response = get_http_headers(ip, 80, use_https=False)
                    server_type = extract_server_type(response)
                elif check_port(ip, 443):
                    console.print("[green]Port 443 open → HTTPS[/green]")
                    response = get_http_headers(ip, 443, use_https=True)
                    server_type = extract_server_type(response)
                else:
                    console.print("[bold red]No HTTP/HTTPS port open or accessible.[/bold red]")
                    return
    
                console.print(f"[bold yellow]Detected Web Server:[/bold yellow] {server_type}")

            if __name__ == "__main__":
                main()
#hidden wifi scanner------------------------------------------------------------------------------

        elif command == '4':
            console=Console()
            def get_ip_location(ip):
                """Fetch geographic location (lat, lon) for a given IP using ip-api."""
                try:
                    response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,lat,lon", timeout=5)
                    data = response.json()
                    if data.get('status') == 'success':
                        return data['lat'], data['lon']
                except Exception:
                    return None
                return None

            def build_google_maps_link(coords):
                """Build Google Maps link for given list of coordinates."""
                if not coords:
                    return None
                base_url = "https://www.google.com/maps/dir/"
                path = "/".join([f"{lat},{lon}" for lat, lon in coords])
                return base_url + path

            def traceroute_udp(target, max_hops=30, timeout=2):
                port = 33434
                hops = []
                coords = []

                try:
                    dest_ip = socket.gethostbyname(target)
                except socket.gaierror:
                    console.print("[bold red]Invalid target address[/bold red]")
                    return [], None

                console.print(f"[bold green]Starting traceroute to:[/bold green] [cyan]{target}[/cyan] ({dest_ip})\n")

                # Table for results
                table = Table(title="Traceroute Results", show_lines=True)
                table.add_column("Hop", justify="center", style="bold yellow")
                table.add_column("IP Address", justify="center", style="cyan")
                table.add_column("Latency (ms)", justify="center", style="bold green")

                with Progress() as progress:
                    task = progress.add_task("[green]Tracing route...", total=max_hops)

                    for ttl in range(1, max_hops + 1):
                        send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                        send_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
                        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                        recv_sock.settimeout(timeout)
                        recv_sock.bind(("", port))

                        start_time = time.time()
                        send_sock.sendto(b"", (target, port))

                        curr_addr = None
                        try:
                            data, addr = recv_sock.recvfrom(512)
                            curr_addr = addr[0]
                            elapsed = (time.time() - start_time) * 1000
                            hops.append(curr_addr)
                            table.add_row(str(ttl), curr_addr, f"{elapsed:.2f}")

                            # Fetch location
                            location = get_ip_location(curr_addr)
                            if location:
                                coords.append(location)

                            if curr_addr == dest_ip:
                                console.print("[bold cyan]\nDestination reached![/bold cyan]")
                                break

                        except socket.timeout:
                            table.add_row(str(ttl), "*", "*")
                        finally:
                            send_sock.close()
                            recv_sock.close()

                        progress.advance(task)

                    console.print("\n", table)
                    map_link = build_google_maps_link(coords)
                    return hops, map_link

                
            target = console.input("Enter destination address: ").strip()
            hops, map_link = traceroute_udp(target)

            if map_link:
                console.print(f"\n[bold magenta]Google Maps Link:[/bold magenta]\n[blue underline]{map_link}[/blue underline]")
            else:
                console.print("\n[red]No coordinates found for map link.[/red]")

        # ---------------------------------------------exit ---------------------------------------

        elif command == '5':
            # Placeholder for help module logic
            print("Help section not implemented yet.")
            sys.exit()

        # ----------------------------------------------return error-------------------------------------
        else:
            console.print("[!] Error: Invalid command..." ,style='red on white')
            mainloop()
mainloop()