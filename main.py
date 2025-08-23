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
#Initial panel---------------------
panel1 = Panel("[bold blue]Network Scanner Script[/]\n[red][1]network scan\n[2]open ports scan\n[3]hidden wifi scan\n[4]web server scan\n[5]exit",title="services list",subtitle="1972Cyrus",title_align='right',subtitle_align='left')

console = Console()
console.print(panel1)

#main code-----------------
def mainloop():
    while True:
#start and services list---
        command = Prompt.ask('[?]:(just number) ' ,choices=["1", "2", "3", "4","5"])

#network scanner-----------
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