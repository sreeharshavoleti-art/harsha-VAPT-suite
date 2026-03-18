# HARSHA AI v10.0 — VAPT Suite 🛡️

> A comprehensive AI-powered Vulnerability Assessment & Penetration Testing suite built with Python + Flask.

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![Flask](https://img.shields.io/badge/Flask-Web%20UI-green)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Tools](https://img.shields.io/badge/Tools-30%2B-red)

---

## 🚀 About

HARSHA AI is a full-featured VAPT suite designed for security professionals.
It combines 30+ security tools into a single AI-powered interface with:
- Real-time scan progress tracking
- AI chat assistant for security concepts
- Wikipedia + DuckDuckGo integrated search
- Voice output support
- Automated threat detection & reporting

---

## ⚡ Features

### 🔍 Network VAPT
| Tool | Description |
|---|---|
| Port Scanner (Quick/Full) | Nmap-based port discovery |
| Vulnerability Scan | CVE detection via Nmap scripts |
| OS Detection | Remote OS fingerprinting |
| UDP Scan | Top 50 UDP ports |
| Firewall Detection | Firewall bypass testing |
| Banner Grab | Service banner enumeration |
| ARP Scan | Local network host discovery |
| SMB Enumeration | Shares, users, MS17-010 check |
| SNMP Enumeration | Community string testing |
| DNS Zone Transfer | Misconfigured DNS detection |

### 🌐 Web VAPT
| Tool | Description |
|---|---|
| HTTP Header Audit | Missing security headers check |
| SSL/TLS Analysis | Cipher strength, Heartbleed, POODLE |
| WAF Detection | wafw00f + Nmap WAF scripts |
| Nikto Web Scan | 6000+ web vulnerability checks |
| Directory Enumeration | Gobuster / Dirb wordlist scan |
| Admin Panel Finder | 20+ common admin paths |
| CMS Detection | WordPress, Joomla, Drupal detect |
| CORS Check | Misconfiguration testing |
| SQL Injection Test | SQLMap automated testing |
| XSS Scanner | Reflected + DOM XSS payloads |
| HTTP Methods Test | PUT/DELETE/TRACE detection |
| Subdomain Enumeration | Common subdomain bruteforce |

### 🏗️ Infrastructure VAPT
| Tool | Description |
|---|---|
| SSH Audit | Weak algorithms, auth methods |
| FTP Check | Anonymous login, bounce check |
| RDP Check | BlueKeep, NLA configuration |
| Database Exposure | MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch |
| Docker/K8s Check | Exposed API, Kubelet, metadata |
| CVE Scan | Full Nmap vuln script suite |
| WinRM Check | Windows Remote Management |
| SNMP Audit | SNMPv1/v2 community testing |

### 🔬 Nuclei Scanner
- Full scan, CVE scan, Misconfiguration scan
- Technology detection, Critical/High severity
- Network-level scanning

### 🌐 Recon Tools
- WHOIS, DNS Records (A/MX/NS/TXT/CNAME)
- IP Geolocation, Ping, Traceroute
- Local Network Scan, Public/Private IP

---

## 🤖 AI Chat Assistant

Built-in knowledge base covering:
- OWASP Top 10, CVSS scoring, CVE database
- SQLi, XSS, CORS, WAF, SSRF, RCE concepts
- Network attacks: MITM, DDoS, Brute Force
- Encryption standards, CIA Triad
- Wikipedia + DuckDuckGo live search

---

## 🛠️ Tech Stack
```
Python 3.8+    — Core language
Flask          — Web UI + REST API
Nmap           — Port & vulnerability scanning
Nikto          — Web vulnerability scanner
Nuclei         — Template-based scanner
SQLMap         — SQL injection testing
Gobuster/Dirb  — Directory enumeration
wafw00f        — WAF detection
gTTS           — Voice output
requests       — HTTP client + IP info
psutil         — System monitoring
```

---

## 📦 Installation
```bash
# Clone the repository
git clone https://github.com/sreeharshavoleti-art/harsha-VAPT-suite.git
cd harsha-VAPT-suite

# Install Python dependencies
pip install flask gtts requests psutil

# Install security tools (Kali Linux / Ubuntu)
sudo apt install nmap nikto gobuster dirb sqlmap whatweb

# Run the suite
python harsha_VAPT.py
```

---

## 🔐 Disclaimer

> This tool is intended for **authorized security testing only**.
> Always obtain written permission before scanning any system.
> The author is not responsible for any misuse.

---

## 👤 Author

**Voleti Sriharsha Vardhan Sharma**
- 💼 IT Security Analyst — Fluentgrid Limited
- 🎓 B.Tech IT — Raghu Engineering College
- 🔗 [LinkedIn](https://linkedin.com/in/sreeharshavardhan-voleti-742249210/)
- 📧 sreeharsha.voleti@gmail.com

---

## ⭐ Star this repo if it helped you!
```

---

