# VulnScanner 🔍    
VulnScanner is a powerful and automated CLI-based web vulnerability scanner written in Python. Designed for professional penetration testers and bug bounty hunters, this tool performs deep analysis and enumeration on websites to discover a wide range of critical security vulnerabilities.

## Features 🚀
Subdomain Enumeration using subfinder 🌐

URL Crawling with BeautifulSoup 🕸️

Automated Vulnerability Scanning ⚡:

SQL Injection (SQLi)

Cross-Site Scripting (XSS)

Server-Side Request Forgery (SSRF)

Local File Inclusion (LFI)

Insecure Direct Object References (IDOR)

Integration with Nuclei for template-based detection 🧠

Automatic Exploit PoC Generation for discovered vulnerabilities 💥

Fast, lightweight, and fully terminal-based 💻

Built for legal and authorized testing only ✅

## Requirements 🛠️
Python 3.8+

### Tools:

- subfinder
- nuclei
- sqlmap
- XSStrike

## Installation 👾
```
git clone https://github.com/Abdelrhman333/Vulnscanner
```
```
chmod +x install.sh
```
```
./install.sh
```
## Usage 🧙‍♂️
```
webscan.py [-h] -u URL [--no-subdomains] [--no-nuclei] [--no-sql] [--no-xss] [--no-ssrf] [--no-lfi] [--no-idor] [--level {1,2,3}]
```
### options: 
```
-h, --help         show this help message and exit
  -u URL, --url URL  Target URL (e.g. https://example.com)
  --no-subdomains    Skip subdomain enumeration.
  --no-nuclei        Skip Nuclei scan.
  --no-sql           Skip SQL Injection scan.
  --no-xss           Skip XSS scan.
  --no-ssrf          Skip SSRF scan.
  --no-lfi           Skip LFI scan.
  --no-idor          Skip IDOR scan.
  --level {1,2,3}    Set scan level (1 is default, 2 and 3 add more depth).
  --output OUTPUT    Specify output file for saving results (e.g. output.json)
```

