#!/usr/bin/env python3
import os
import sys
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from modules import recon, network, web, brute, exploit, defensive, utils

console = Console()
VERSION = "Ultimate v4.0"
LAST_UPDATE = "2024-06-30"
REPO_URL = "https://github.com/RizkySec/RizkySec-Toolkit"

# Global settings
MODE = "beginner"  # beginner or expert
TELEGRAM_ENABLED = True
REPORT_DIR = "reports"

def show_banner():
    ascii_art = """
██████╗ ██╗███████╗███████╗██╗  ██╗██╗   ██╗
██╔══██╗██║╚══███╔╝╚══███╔╝██║ ██╔╝╚██╗ ██╔╝
██████╔╝██║  ███╔╝   ███╔╝ █████╔╝  ╚████╔╝ 
██╔══██╗██║ ███╔╝   ███╔╝  ██╔═██╗   ╚██╔╝  
██║  ██║██║███████╗███████╗██║  ██╗   ██║   
╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═╝  ╚═╝   ╚═╝   
"""
    title = f"Riezky As {VERSION}"
    console.print(Panel.fit(ascii_art, title=title, style="bold blue"))
    console.print(Panel.fit(
        "[bold yellow]DISCLAIMER:[/bold yellow] Use only with explicit permission! Unauthorized access is illegal and unethical. Developers are not responsible for misuse.",
        style="red"
    ))
    console.print(f"[bold cyan]System: {sys.platform} | Python: {sys.version.split()[0]} | Mode: {MODE.capitalize()}[/bold cyan]")

def main_menu():
    show_banner()
    while True:
        console.print("\n[bold cyan]Riezky As Main Menu[/bold cyan]")
        console.print("="*60)
        console.print("[bold yellow]1. RECONNAISSANCE[/bold yellow]")
        console.print("[bold yellow]2. NETWORK SCANNING[/bold yellow]")
        console.print("[bold yellow]3. WEB APPLICATION[/bold yellow]")
        console.print("[bold yellow]4. BRUTE FORCE & EXPLOITATION[/bold yellow]")
        console.print("[bold yellow]5. DEFENSIVE TOOLS[/bold yellow]")
        console.print("[bold yellow]6. UTILITIES[/bold yellow]")
        console.print("[bold yellow]0. EXIT[/bold yellow]")
        console.print("="*60)
        
        choice = console.input("[bold green]Select category (0-6): [/]").strip()
        
        if choice == "1":
            recon_menu()
        elif choice == "2":
            network_menu()
        elif choice == "3":
            web_menu()
        elif choice == "4":
            exploit_menu()
        elif choice == "5":
            defensive_menu()
        elif choice == "6":
            utils_menu()
        elif choice == "0":
            console.print(Panel.fit("[bold red]Exiting Riezky As...[/bold red]", title="Goodbye", style="red"))
            utils.send_to_telegram("🔴 <b>RIEZKY AS SESSION ENDED</b>")
            break
        else:
            console.print("[red]Invalid choice![/red]")

def recon_menu():
    while True:
        console.print("\n[bold cyan]Reconnaissance Tools[/bold cyan]")
        console.print("="*60)
        console.print("1. WHOIS Lookup - Informasi registrasi domain")
        console.print("2. DNS Lookup - Catatan DNS domain")
        console.print("3. Reverse IP Lookup - Domain di IP yang sama")
        console.print("4. GeoIP Lookup - Informasi geografis IP")
        console.print("5. Email Harvester - Kumpulkan email terkait domain")
        console.print("6. User Recon - Cari username di sosial media")
        console.print("7. Subdomain Enum - Temukan subdomain terkait domain")
        console.print("8. Shodan Lookup - Informasi perangkat internet (API key dibutuhkan)")
        console.print("0. Back to Main Menu")
        console.print("="*60)
        
        choice = console.input("[bold green]Select tool (0-8): [/]").strip()
        
        mode = get_mode()
        target = None
        if choice not in ["0", "8"]:  # Shodan doesn't require target in the same way
            target = console.input("[bold green]Enter target: [/]").strip()
        
        try:
            if choice == "1":
                recon.whois_lookup(target, mode)
            elif choice == "2":
                recon.dns_lookup(target, mode)
            elif choice == "3":
                recon.reverse_ip_lookup(target)
            elif choice == "4":
                recon.geoip_lookup(target)
            elif choice == "5":
                recon.email_harvester(target, mode)
            elif choice == "6":
                username = console.input("[bold green]Enter username: [/]").strip()
                recon.userrecon_scan(username, mode)
            elif choice == "7":
                recon.subdomain_enum(target, mode)
            elif choice == "8":
                query = console.input("[bold green]Enter Shodan query: [/]").strip()
                exploit.shodan_lookup(query)
            elif choice == "0":
                break
            else:
                console.print("[red]Invalid choice![/red]")
        except Exception as e:
            console.print(f"[bold red]Error: {str(e)}[/bold red]")
            utils.send_to_telegram(f"⚠️ <b>ERROR IN RECON TOOL</b>\n{str(e)}")

def network_menu():
    while True:
        console.print("\n[bold cyan]Network Scanning Tools[/bold cyan]")
        console.print("="*60)
        console.print("1. Nmap Scan - Pemindaian port dan layanan")
        console.print("2. Port Scanner - Pemindaian port cepat")
        console.print("3. Traceroute - Lacak rute jaringan")
        console.print("4. Subnet Lookup - Analisis informasi subnet")
        console.print("0. Back to Main Menu")
        console.print("="*60)
        
        choice = console.input("[bold green]Select tool (0-4): [/]").strip()
        
        mode = get_mode()
        target = None
        if choice != "0":
            target = console.input("[bold green]Enter target: [/]").strip()
        
        try:
            if choice == "1":
                network.nmap_scan(target, mode)
            elif choice == "2":
                network.port_scanner(target, mode)
            elif choice == "3":
                network.traceroute(target, mode)
            elif choice == "4":
                network.subnet_lookup(target)
            elif choice == "0":
                break
            else:
                console.print("[red]Invalid choice![/red]")
        except Exception as e:
            console.print(f"[bold red]Error: {str(e)}[/bold red]")
            utils.send_to_telegram(f"⚠️ <b>ERROR IN NETWORK TOOL</b>\n{str(e)}")

def web_menu():
    while True:
        console.print("\n[bold cyan]Web Application Tools[/bold cyan]")
        console.print("="*60)
        console.print("1. WhatWeb Scan - Identifikasi teknologi web")
        console.print("2. Gobuster Scan - Cari direktori dan file tersembunyi")
        console.print("3. WAF Detection - Deteksi Web Application Firewall")
        console.print("4. Nuclei Scan - Pemindaian kerentanan otomatis")
        console.print("5. HTTP Header Analysis - Analisis header keamanan")
        console.print("6. robots.txt Scanner - Periksa isi robots.txt")
        console.print("7. Zone Transfer Check - Periksa kerentanan DNS")
        console.print("8. SSL/TLS Scanner - Periksa konfigurasi SSL/TLS")
        console.print("9. Login Page Finder - Cari halaman login/admin")
        console.print("10. CMS Detector - Identifikasi CMS & plugin")
        console.print("11. SQL Injection Scanner - Deteksi kerentanan SQLi")
        console.print("12. XSS Scanner - Deteksi kerentanan Cross-Site Scripting")
        console.print("13. SSRF Tester - Uji kerentanan Server-Side Request Forgery")
        console.print("14. LFI/RFI Tester - Uji kerentanan file inclusion")
        console.print("0. Back to Main Menu")
        console.print("="*60)
        
        choice = console.input("[bold green]Select tool (0-14): [/]").strip()
        
        mode = get_mode()
        target = None
        if choice != "0":
            target = console.input("[bold green]Enter target: [/]").strip()
        
        try:
            if choice == "1":
                web.whatweb_scan(target, mode)
            elif choice == "2":
                web.gobuster_scan(target, mode)
            elif choice == "3":
                web.waf_detection(target, mode)
            elif choice == "4":
                web.nuclei_scan(target, mode)
            elif choice == "5":
                web.http_header_analysis(target)
            elif choice == "6":
                web.robots_txt_scanner(target)
            elif choice == "7":
                web.zone_transfer_check(target)
            elif choice == "8":
                web.ssl_tls_scan(target)
            elif choice == "9":
                web.find_login_pages(target, mode)
            elif choice == "10":
                web.cms_detector(target)
            elif choice == "11":
                web.sql_injection_scan(target)
            elif choice == "12":
                web.xss_scan(target)
            elif choice == "13":
                web.ssrf_test(target)
            elif choice == "14":
                web.lfi_rfi_test(target)
            elif choice == "0":
                break
            else:
                console.print("[red]Invalid choice![/red]")
        except Exception as e:
            console.print(f"[bold red]Error: {str(e)}[/bold red]")
            utils.send_to_telegram(f"⚠️ <b>ERROR IN WEB TOOL</b>\n{str(e)}")

def exploit_menu():
    while True:
        console.print("\n[bold cyan]Brute Force & Exploitation[/bold cyan]")
        console.print("="*60)
        console.print("1. Brute Force Attack - FTP/SSH/HTTP/WordPress/cPanel")
        console.print("2. Webshell Detector - Cari backdoor di website")
        console.print("3. CVE Scanner - Log4Shell & kerentanan kritis")
        console.print("4. Generate Reverse Shell - Buat payload reverse shell")
        console.print("5. ExploitDB Search - Cari exploit untuk CVE/layanan")
        console.print("0. Back to Main Menu")
        console.print("="*60)
        
        choice = console.input("[bold green]Select tool (0-5): [/]").strip()
        
        mode = get_mode()
        target = None
        if choice not in ["0", "4", "5"]:  # These don't require target
            target = console.input("[bold green]Enter target: [/]").strip()
        
        try:
            if choice == "1":
                service = console.input("[bold green]Enter service (ftp/ssh/http-form/wordpress/cpanel): [/]").strip()
                username = None
                if service != "http-form":
                    username = console.input("[bold green]Enter username (or leave blank for user list): [/]").strip() or None
                brute.brute_force_attack(target, service, username, mode)
            elif choice == "2":
                exploit.detect_webshells(target)
            elif choice == "3":
                exploit.cve_scanner(target)
            elif choice == "4":
                exploit.generate_reverse_shell()
            elif choice == "5":
                query = console.input("[bold green]Enter CVE/service name: [/]").strip()
                exploit.exploitdb_search(query)
            elif choice == "0":
                break
            else:
                console.print("[red]Invalid choice![/red]")
        except Exception as e:
            console.print(f"[bold red]Error: {str(e)}[/bold red]")
            utils.send_to_telegram(f"⚠️ <b>ERROR IN EXPLOIT TOOL</b>\n{str(e)}")

def defensive_menu():
    while True:
        console.print("\n[bold cyan]Defensive Tools[/bold cyan]")
        console.print("="*60)
        console.print("1. Malware Scanner - Cek file dengan VirusTotal")
        console.print("2. Traffic Monitor - Pantau koneksi jaringan")
        console.print("0. Back to Main Menu")
        console.print("="*60)
        
        choice = console.input("[bold green]Select tool (0-2): [/]").strip()
        
        try:
            if choice == "1":
                file_path = console.input("[bold green]Enter file path: [/]").strip()
                defensive.malware_scan(file_path)
            elif choice == "2":
                duration = console.input("[bold green]Enter duration in seconds: [/]").strip() or "30"
                defensive.monitor_traffic(int(duration))
            elif choice == "0":
                break
            else:
                console.print("[red]Invalid choice![/red]")
        except Exception as e:
            console.print(f"[bold red]Error: {str(e)}[/bold red]")
            utils.send_to_telegram(f"⚠️ <b>ERROR IN DEFENSIVE TOOL</b>\n{str(e)}")

def utils_menu():
    while True:
        console.print("\n[bold cyan]Utilities[/bold cyan]")
        console.print("="*60)
        console.print("1. Update Toolkit - Perbarui toolkit dan dependensi")
        console.print("2. Install Dependencies - Instal semua dependensi")
        console.print("3. Switch Mode - Ganti mode (Beginner/Expert)")
        console.print("4. Generate HTML Report - Buat laporan HTML")
        console.print("5. About - Informasi tentang toolkit")
        console.print("0. Back to Main Menu")
        console.print("="*60)
        
        choice = console.input("[bold green]Select option (0-5): [/]").strip()
        
        try:
            if choice == "1":
                utils.update_toolkit()
            elif choice == "2":
                utils.install_dependencies()
            elif choice == "3":
                switch_mode()
            elif choice == "4":
                target = console.input("[bold green]Enter target name for report: [/]").strip()
                utils.generate_html_report(target)
            elif choice == "5":
                utils.about()
            elif choice == "0":
                break
            else:
                console.print("[red]Invalid choice![/red]")
        except Exception as e:
            console.print(f"[bold red]Error: {str(e)}[/bold red]")
            utils.send_to_telegram(f"⚠️ <b>ERROR IN UTILITY</b>\n{str(e)}")

def get_mode():
    if MODE == "beginner":
        return "beginner"
    return "expert"

def switch_mode():
    global MODE
    current = MODE.capitalize()
    new_mode = "expert" if MODE == "beginner" else "beginner"
    console.print(f"[yellow]Switching mode from {current} to {new_mode.capitalize()}[/yellow]")
    MODE = new_mode

if __name__ == "__main__":
    # Check and create report directory
    os.makedirs(REPORT_DIR, exist_ok=True)
    os.makedirs("wordlists", exist_ok=True)
    
    # Setup environment
    go_path = os.path.expanduser("~/go/bin")
    if go_path not in os.environ["PATH"]:
        os.environ["PATH"] += os.pathsep + go_path
    
    # Send startup notification
    utils.send_to_telegram(f"🟢 <b>RIEZKY AS {VERSION} STARTED</b>\nSystem: {sys.platform}\nPython: {sys.version.split()[0]}")
    
    main_menu()