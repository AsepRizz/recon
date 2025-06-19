import os
import time
import re
import dns.resolver
import requests
import json
import concurrent.futures
import threading
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from modules.utils import *

console = Console()

def whois_lookup(target, mode="cepat"):
    """
    WHOIS digunakan untuk melihat informasi pendaftaran domain, 
    seperti siapa pemilik domain dan kapan domain dibuat.
    """
    if mode == "beginner":
        console.print(Panel.fit(
            "WHOIS digunakan untuk melihat informasi pendaftaran domain, seperti siapa pemilik domain dan kapan domain dibuat.",
            title="Penjelasan WHOIS",
            style="blue"
        ))
    
    if not ensure_tool("whois", "sudo apt install whois -y"):
        return
    
    console.print("[yellow]⏳ Running WHOIS lookup...[/yellow]")
    command = ["whois", "-H", target] if mode == "cepat" else ["whois", target]
    
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
        output = result.stdout if result.returncode == 0 else result.stderr
        
        console.print(Panel.fit(output, title="WHOIS Results", style="green"))
        telegram_msg = f"<b>🔍 WHOIS RESULTS FOR {target}</b>\n<pre>{clean_ansi_codes(output)}</pre>"
        send_to_telegram(telegram_msg)
        generate_html_report_section(target, "WHOIS Lookup", output)
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

# Fungsi recon lainnya (DNS, Reverse IP, GeoIP, dll) akan didefinisikan di sini...