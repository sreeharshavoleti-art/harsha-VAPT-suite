<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=32&duration=3000&pause=1000&color=00FF41&center=true&vCenter=true&width=600&lines=HARSHA+AI+v10.0;VAPT+Suite;Vulnerability+%26+Penetration+Testing" alt="Typing SVG" />

<br/>

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-Web%20UI-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![Nmap](https://img.shields.io/badge/Nmap-Integrated-4CAF50?style=for-the-badge&logo=linux&logoColor=white)](https://nmap.org)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)
[![Tools](https://img.shields.io/badge/Tools-30%2B-red?style=for-the-badge&logo=hackthebox&logoColor=white)](https://github.com/sreeharshavoleti-art/harsha-VAPT-suite)
[![Lines](https://img.shields.io/badge/Lines%20of%20Code-2487-blueviolet?style=for-the-badge)](https://github.com/sreeharshavoleti-art/harsha-VAPT-suite)

<br/>

> **A comprehensive AI-powered Vulnerability Assessment & Penetration Testing framework.**  
> Built for security professionals. Covers Web, Network, Infrastructure, and Cloud security testing with 30+ integrated tools, real-time scan progress, and an intelligent AI chat assistant.

<br/>

[🚀 Quick Start](#-installation) · [🛠️ Tools](#️-tools--capabilities) · [🤖 AI Assistant](#-ai-chat-assistant) · [📸 Usage](#-usage) · [👤 Author](#-author)

---

</div>

## 📌 Overview

**HARSHA AI v10.0** is a Flask-powered VAPT suite that unifies the most critical security testing workflows into a single, intelligent interface. Instead of switching between dozens of terminal tools, security analysts can launch assessments, monitor real-time progress, and receive AI-guided remediation advice — all from one place.

**Key differentiators:**
- 🤖 **Built-in AI chat** — answers security questions, explains CVEs, OWASP, and attack techniques
- 📡 **Live search** — Wikipedia + DuckDuckGo integrated for real-time threat intelligence
- 🔊 **Voice output** — gTTS-powered audio feedback (India English accent)
- 📊 **Risk visualization** — threat graphs, severity ratings, port intelligence database
- ⚡ **Progress tracking** — real-time scan status with percentage and elapsed time
- 📄 **Auto reporting** — downloadable VAPT reports per assessment

---

## 🛠️ Tools & Capabilities

### 🔍 Network VAPT — 10 Tools

| Tool | Command | Description |
|------|---------|-------------|
| **Port Scanner (Quick)** | `nmap -Pn -T4 -F --open` | Fast top-100 port discovery |
| **Port Scanner (Full)** | `nmap -Pn -T4 -sV -sC -A` | Full service + version detection |
| **Vulnerability Scan** | `nmap --script vuln -sV` | CVE detection via NSE scripts |
| **OS Detection** | `nmap -O -sV` | Remote operating system fingerprinting |
| **UDP Scan** | `nmap -sU --top-ports 50` | Top 50 UDP service discovery |
| **Firewall Detection** | `nmap -sA + firewall-bypass` | ACK scan + bypass script |
| **Banner Grab** | `nmap --script banner` | Service banner enumeration |
| **ARP Scan** | `nmap -sn <subnet>` | Local network host discovery |
| **SMB Enumeration** | `smb-enum-shares + enum4linux` | Shares, users, MS17-010 EternalBlue |
| **SNMP Enumeration** | `snmpwalk + nmap SNMP scripts` | Community string testing |

### 🌐 Web VAPT — 12 Tools

| Tool | Engine | Description |
|------|--------|-------------|
| **HTTP Header Audit** | `curl -sI` | Detects missing security headers (CSP, HSTS, X-Frame) |
| **SSL/TLS Analysis** | `openssl + nmap ssl-*` | Cipher strength, Heartbleed, POODLE, DROWN |
| **WAF Detection** | `wafw00f + nmap http-waf-*` | Identifies WAF vendor and bypass potential |
| **Nikto Web Scan** | `nikto` | 6700+ web vulnerability signatures |
| **Directory Enumeration** | `gobuster / dirb` | Wordlist-based path discovery |
| **Admin Panel Finder** | Custom crawler | 20+ common admin paths tested |
| **CMS Detection** | `whatweb + wpscan` | WordPress, Joomla, Drupal fingerprinting |
| **CORS Check** | `curl + nmap http-cors` | Misconfigured cross-origin policy detection |
| **SQL Injection Test** | `sqlmap --batch` | Automated SQLi with form crawling |
| **XSS Scanner** | `nmap http-xss-* + payloads` | Reflected, stored, DOM-based XSS testing |
| **HTTP Methods Test** | `curl -X <METHOD>` | PUT/DELETE/TRACE/CONNECT exposure |
| **Subdomain Enumeration** | DNS bruteforce | 40+ common subdomains tested |

### 🏗️ Infrastructure VAPT — 8 Tools

| Tool | Checks |
|------|--------|
| **SSH Audit** | Weak algorithms, root login, auth methods, ssh-audit |
| **FTP Check** | Anonymous login, bounce attack, CVE-2010-4221 |
| **RDP Check** | BlueKeep (CVE-2019-0708), MS12-020, NLA config |
| **Database Exposure** | MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch |
| **Docker/K8s Check** | Docker API (2375), Kubelet (10250), AWS metadata |
| **CVE Scan** | Full `nmap --script vuln + exploit` suite |
| **WinRM Check** | Windows Remote Management HTTP/HTTPS |
| **SNMP Audit** | SNMPv1/v2 brute + interface/process enumeration |

### 🔬 Nuclei Scanner — 6 Templates

| Scan Type | Template | Severity Filter |
|-----------|----------|----------------|
| Full Scan | All templates | All |
| CVE Scan | `cves/` | Critical, High |
| Misconfiguration | `misconfiguration/ + exposed-panels/` | All |
| Technology Detect | `technologies/` | All |
| Critical/High | All templates | Critical, High only |
| Network Scan | `network/` | All |

### 🌐 Recon Tools — 8 Tools

`WHOIS` · `DNS Records (A/MX/NS/TXT/CNAME/SOA/AAAA)` · `IP Geolocation` · `Ping` · `Traceroute` · `Local Network Scan` · `My IP (Public + Private)` · `System Info`

---

## 🤖 AI Chat Assistant

The built-in AI assistant covers **cybersecurity knowledge** without needing internet:

```
Ask: "What is SQL injection?"        → Full explanation + attack types + prevention
Ask: "Explain OWASP Top 10"          → All 10 with context
Ask: "How to secure SSH?"            → 8 hardening best practices
Ask: "What is CVSS scoring?"         → Scoring breakdown with ranges
Ask: "Explain Log4Shell"             → CVE-2021-44228 full analysis
Ask: "Search Cloudflare WAF"         → Live Wikipedia/DuckDuckGo result
```

**Topics covered:** SQLi, XSS, CORS, WAF, SSRF, RCE, MITM, DDoS, Ransomware, Phishing, Zero-day, Brute Force, Social Engineering, CIA Triad, Encryption standards, TLS best practices, Docker/K8s security, OWASP API Top 10, and more.

---

## 🧠 Intelligence Database

### Port Knowledge Base — 50+ Ports
Every detected open port is cross-referenced against a built-in database:

```python
PORT 6379 → Redis
Severity : CRITICAL
Risk     : Redis has no auth by default. Full database read/write/RCE possible.
Fix      : Set requirepass in redis.conf. Bind to 127.0.0.1 only.
```

### Vulnerability Database — 25+ CVEs
Auto-detected from scan output:

| CVE | Name | Severity |
|-----|------|----------|
| CVE-2017-0144 | EternalBlue / MS17-010 (WannaCry) | 🔴 CRITICAL |
| CVE-2021-44228 | Log4Shell | 🔴 CRITICAL |
| CVE-2019-0708 | BlueKeep (RDP) | 🔴 CRITICAL |
| CVE-2014-0160 | Heartbleed | 🔴 CRITICAL |
| CVE-2021-34527 | PrintNightmare | 🔴 CRITICAL |
| CVE-2020-1472 | ZeroLogon | 🔴 CRITICAL |
| CVE-2014-6271 | Shellshock | 🔴 CRITICAL |
| CVE-2014-3566 | POODLE (SSLv3) | 🟠 HIGH |
| FTP Anonymous | FTP Anonymous Login | 🟠 HIGH |
| Missing HSTS | No Strict-Transport-Security | 🟡 MEDIUM |

---

## 🚀 Installation

### Prerequisites

```bash
# Python 3.8+
python --version

# Kali Linux / Ubuntu (recommended)
sudo apt update
```

### Install

```bash
# Clone repository
git clone https://github.com/sreeharshavoleti-art/harsha-VAPT-suite.git
cd harsha-VAPT-suite

# Install Python dependencies
pip install flask gtts requests psutil

# Install security tools
sudo apt install -y nmap nikto gobuster dirb sqlmap whatweb wpscan nuclei

# Optional: wafw00f, ssh-audit
pip install wafw00f
sudo apt install ssh-audit

# Run HARSHA AI
python harsha_VAPT.py
```

### Access

```
Open browser → http://localhost:5000
```

---

## 📋 Usage

```
1. Enter target IP or domain in the TARGET field
2. Select a tool from the sidebar (Network / Web / Infra / Recon / Nuclei)
3. Watch real-time scan progress with percentage and elapsed time
4. View results in Terminal tab
5. Open Ports tab → severity-rated port analysis
6. Open Threats tab → detected CVEs with fix guidance
7. Download Report → full VAPT PDF report
8. Chat tab → ask AI security questions
```

---

## 🏗️ Architecture

```
harsha-VAPT-suite/
│
├── harsha_VAPT.py          # Core engine — 2487 lines
│   ├── Flask API           # /scan, /chat, /voice, /status endpoints
│   ├── Scan Engine         # 30+ tool handlers with subprocess
│   ├── Progress Tracker    # Real-time threading with % completion
│   ├── Port DB             # 50+ ports with severity + fix
│   ├── Vuln DB             # 25+ CVE signatures
│   ├── AI Chat Engine      # Keyword + NLP response system
│   ├── Search Engine       # Wikipedia + DuckDuckGo integration
│   └── Nuclei Integration  # 6 template-based scan types
│
└── README.md
```

---

## ⚙️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.8+, Flask |
| Scanning | Nmap, Nikto, Nuclei, SQLMap, Gobuster |
| Web Testing | wafw00f, whatweb, wpscan, curl |
| AI/Search | Wikipedia API, DuckDuckGo API |
| Voice | gTTS (Google Text-to-Speech) |
| System | psutil, threading, subprocess |
| Networking | requests, socket, DNS (dig) |

---

## ⚠️ Legal Disclaimer

> **This tool is developed strictly for authorized security testing and educational purposes.**  
> Scanning systems without explicit written permission is **illegal** under the Computer Fraud and Abuse Act (CFAA), IT Act 2000 (India), and other applicable laws.  
> The author assumes **no liability** for any unauthorized or illegal use of this software.  
> **Always obtain proper authorization before conducting any security assessment.**

---

## 👤 Author

<table>
<tr>
<td align="center">
<b>Voleti Sriharsha Vardhan Sharma</b><br/>
IT Security Analyst | VAPT Engineer | M.Tech Aspirant 2026<br/><br/>
<a href="https://linkedin.com/in/sreeharshavardhan-voleti-742249210/">
<img src="https://img.shields.io/badge/LinkedIn-Connect-0A66C2?style=for-the-badge&logo=linkedin"/>
</a>
&nbsp;
<a href="mailto:sreeharsha.voleti@gmail.com">
<img src="https://img.shields.io/badge/Email-Contact-EA4335?style=for-the-badge&logo=gmail&logoColor=white"/>
</a>
<br/><br/>
📍 India<br/>
🏢 cyber security research <br/>
<br/>
</td>
</tr>
</table>

---

## ⭐ Support

If this project helped you, please consider giving it a ⭐ star — it helps others discover it!

```
git clone https://github.com/sreeharshavoleti-art/harsha-VAPT-suite.git
```

---

<div align="center">

**Built with ❤️ by Harsha | India | 2025**

*"The best hackers think like attackers but act like defenders."*

</div>
