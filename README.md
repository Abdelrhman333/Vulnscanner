# VulnScanner 🔍
VulnScanner is a powerful and automated CLI-based web vulnerability scanner written in Python. Designed for professional penetration testers and bug bounty hunters, this tool performs deep analysis and enumeration on websites to discover a wide 
range of critical security vulnerabilities.

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
vulnscanner.py -u URL [-h]
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
## Contact & Support

If you need help or have any questions, you can contact us via email:

abdoislam732@gmail.com

## License
This project is licensed under the  Apache-2.0 license - see the [LICENSE](https://github.com/Abdelrhman333/Vulnscanner?tab=Apache-2.0-1-ov-file) file for details.


