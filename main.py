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

