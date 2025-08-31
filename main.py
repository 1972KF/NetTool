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
from rich.panel import Panel
from rich.console import Console, Group
# other-------------------------------
import re
import socket 
from datetime import datetime
import sys
import ssl
#Initial panel---------------------
panel1 = Panel("[bold blue]Network Scanner Script[/]\n[red][1]network scan\n[2]open ports scan\n[3]hidden wifi scan\n[4]web server scan\n[5]exit",title="services list",subtitle="1972Cyrus",title_align='right',subtitle_align='left')

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
            pass # Placeholder for wifi scanner module logic

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