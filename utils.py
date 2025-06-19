import os
import sys
import time
import json
import html
import subprocess
import shutil
import requests
from rich.console import Console

console = Console()
VERSION = "Ultimate v4.0"
LAST_UPDATE = "2024-06-30"
REPO_URL = "https://github.com/RizkySec/RizkySec-Toolkit"

# Konfigurasi Telegram
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "8127930072:AAHwbMBROwSrXSRFTPL4RgdNunzrKqgisHU")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "5731047913")

def clean_ansi_codes(text):
    """Hapus kode ANSI dan escape karakter HTML dari teks"""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    clean_text = ansi_escape.sub('', text)
    return html.escape(clean_text)

def send_to_telegram(message):
    """Kirim hasil scan ke Telegram"""
    try:
        if not TELEGRAM_TOKEN or TELEGRAM_TOKEN == "your_default_token":
            return False

        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "HTML"
        }
        response = requests.post(url, json=payload, timeout=10)
        return response.status_code == 200
    except Exception as e:
        console.print(f"[red]Error Telegram: {str(e)}[/red]")
        return False

def send_file_to_telegram(file_path, caption=""):
    """Kirim file hasil scan ke Telegram"""
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendDocument"
        with open(file_path, 'rb') as file:
            files = {'document': file}
            data = {'chat_id': TELEGRAM_CHAT_ID, 'caption': caption}
            response = requests.post(url, files=files, data=data, timeout=30)
        return response.status_code == 200
    except Exception as e:
        console.print(f"[red]Error kirim file: {str(e)}[/red]")
        return False

def check_tool(tool_name):
    return shutil.which(tool_name) is not None

def install_tool(tool_name, install_command):
    console.print(f"[yellow]⏳ Installing {tool_name}...[/yellow]")
    try:
        if "go install" in install_command:
            result = subprocess.run(install_command.split(), capture_output=True, text=True)
            if result.returncode == 0:
                go_path = os.path.expanduser("~/go/bin")
                if go_path not in os.environ["PATH"]:
                    os.environ["PATH"] += os.pathsep + go_path
                return True
        else:
            result = subprocess.run(install_command, shell=True, capture_output=True, text=True)
            return result.returncode == 0
    except Exception as e:
        console.print(f"[red]Error installing {tool_name}: {str(e)}[/red]")
        return False

def ensure_tool(tool_name, install_command):
    if check_tool(tool_name):
        return True
    console.print(f"[yellow]⚠️ {tool_name} not found. Installing...[/yellow]")
    return install_tool(tool_name, install_command)

def detect_protocol(target):
    try:
        response = requests.head(f"https://{target}", timeout=5, verify=False, allow_redirects=True)
        if response.status_code < 400:
            return "https"
    except:
        pass
    return "http"

def get_user_agents():
    return [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    ]

def update_toolkit():
    """Memperbarui toolkit dan semua dependensi"""
    console.print("[yellow]⏳ Updating Riezky As Toolkit...[/yellow]")
    
    try:
        # Update system packages
        subprocess.run(["sudo", "apt", "update"], check=True)
        subprocess.run(["sudo", "apt", "upgrade", "-y"], check=True)
        
        # Update Go tools
        go_tools = [
            "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "github.com/projectdiscovery/httpx/cmd/httpx@latest",
            "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
            "github.com/OJ/gobuster/v3@latest",
            "github.com/tomnomnom/assetfinder@latest",
            "github.com/tomnomnom/httprobe@latest"
        ]
        
        for tool in go_tools:
            subprocess.run(["go", "install", "-v", tool], check=True)
        
        # Update Python tools
        subprocess.run(["pip", "install", "--upgrade", "wafw00f", "theHarvester", "requests"], check=True)
        
        # Update Nuclei templates
        subprocess.run(["nuclei", "-update-templates"], check=True)
        
        # Update testssl.sh
        testssl_dir = os.path.expanduser("~/tools/testssl.sh")
        if os.path.exists(testssl_dir):
            subprocess.run(["git", "-C", testssl_dir, "pull"], check=True)
        
        console.print("[green]✓ Toolkit updated successfully![/green]")
        send_to_telegram("🔄 <b>RIEZKY AS TOOLKIT UPDATED</b>\nAll tools and templates have been updated")
    except Exception as e:
        console.print(f"[red]Update failed: {str(e)}[/red]")
        send_to_telegram(f"❌ <b>UPDATE FAILED</b>\nError: {str(e)}")

def install_dependencies():
    """Menginstal semua dependensi yang diperlukan"""
    console.print("[yellow]⏳ Installing all dependencies...[/yellow]")
    
    dependencies = [
        ("python3-pip", "sudo apt install python3-pip -y"),
        ("git", "sudo apt install git -y"),
        ("golang", "sudo apt install golang -y"),
        ("whois", "sudo apt install whois -y"),
        ("nmap", "sudo apt install nmap -y"),
        ("dnsutils", "sudo apt install dnsutils -y"),
        ("traceroute", "sudo apt install traceroute -y"),
        ("sqlmap", "sudo apt install sqlmap -y"),
        ("wpscan", "sudo apt install wpscan -y")
    ]
    
    results = []
    for tool, cmd in dependencies:
        if not check_tool(tool.split()[0]):
            results.append(f"Installing {tool}...")
            if install_tool(tool, cmd):
                results.append(f"[green]✓ {tool} installed[/green]")
            else:
                results.append(f"[red]✗ Failed to install {tool}[/red]")
        else:
            results.append(f"[green]✓ {tool} already installed[/green]")
    
    console.print(Panel.fit("\n".join(results), title="Dependency Installation", style="cyan"))
    telegram_msg = f"<b>⚙️ DEPENDENCY INSTALLATION</b>\n<pre>{clean_ansi_codes('\n'.join(results))}</pre>"
    send_to_telegram(telegram_msg)

def about():
    """Menampilkan informasi tentang toolkit"""
    about_text = f"""
    Riezky As {VERSION}
    {LAST_UPDATE}
    
    [bold]Created by:[/bold] Rizky Hacker
    [bold]Contact:[/bold] @RizkySec
    
    [bold]Integrated Tools:[/bold]
      • Nmap
      • GoBuster
      • WhatWeb
      • Nuclei
      • Wafw00f
      • theHarvester
      • SubFinder
      • httpx
      • testssl.sh
      • Hydra
      • SQLMap
      • WPScan
      • Shodan API
      • ExploitDB
      • +40 custom modules
    
    [bold]Features:[/bold]
      • Comprehensive network scanning
      • Web application testing
      • Vulnerability assessment
      • Brute force attacks
      • Malware scanning
      • Reverse shell generation
      • Automated reporting to Telegram
      • Real-time progress monitoring
      • Beginner/Expert modes
      • HTML report generation
    
    [bold]Repository:[/bold] {REPO_URL}
    [bold]Disclaimer:[/bold] For authorized security testing only
    """
    
    console.print(Panel.fit(about_text, title="About Riezky As", style="blue"))
    send_to_telegram(f"<b>ℹ️ ABOUT RIEZKY AS {VERSION}</b>\n{about_text}")

def generate_html_report(target):
    """Membuat laporan HTML dari hasil scan"""
    report_file = f"reports/report_{target}.html"
    try:
        with open(report_file, "w") as f:
            f.write(f"<html><head><title>Scan Report for {target}</title></head><body>")
            f.write(f"<h1>Scan Report for {target}</h1>")
            f.write(f"<p>Generated by Riezky As {VERSION} on {time.ctime()}</p>")
            f.write("<h2>Scan Results</h2>")
            
            # Add scan results from various modules
            f.write("<h3>Reconnaissance</h3>")
            # ... (akan diisi dengan hasil scan aktual)
            
            f.write("<h3>Network Scanning</h3>")
            # ... (akan diisi dengan hasil scan aktual)
            
            f.write("</body></html>")
        
        console.print(f"[green]✓ HTML report generated: {report_file}[/green]")
        send_to_telegram(f"📊 <b>HTML REPORT GENERATED FOR {target}</b>")
    except Exception as e:
        console.print(f"[red]Error generating report: {str(e)}[/red]")