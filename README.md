<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=28&pause=1000&color=00FF41&center=true&vCenter=true&width=700&lines=HARSHA+AI+v10.0+%7C+VAPT+Suite+%F0%9F%9B%A1%EF%B8%8F; Vulnerability+Assessment+%26+Penetration+Testing;Web+%7C+Network+%7C+Infrastructure+%7C+Cloud" alt="Typing SVG" />

<br/>

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-Web%20UI-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![Nmap](https://img.shields.io/badge/Nmap-Integrated-4CAF50?style=for-the-badge&logo=linux&logoColor=white)](https://nmap.org)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)
[![Tools](https://img.shields.io/badge/Tools-30%2B-E74C3C?style=for-the-badge&logo=hackthebox&logoColor=white)](https://github.com/sreeharshavoleti-art/harsha-VAPT-suite)
[![Lines](https://img.shields.io/badge/Lines%20of%20Code-2487-8E44AD?style=for-the-badge)](https://github.com/sreeharshavoleti-art/harsha-VAPT-suite)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-268BEE?style=for-the-badge&logo=kalilinux&logoColor=white)](https://kali.org)

<br/>

> **A comprehensive AI-powered Vulnerability Assessment & Penetration Testing framework.**
> Built for security professionals. Covers Web, Network, Infrastructure & Cloud security with 30+ integrated tools,
> real-time scan progress tracking, and an intelligent AI chat assistant.

<br/>

[🚀 Quick Start](#-installation) · [🛠️ Tools](#️-tools--capabilities) · [🤖 AI Chat](#-ai-chat-assistant) · [📦 Install](#-installation) · [👤 Author](#-author)

---

</div>

## 📌 Overview

**HARSHA AI v10.0** is a Flask-powered VAPT suite that unifies the most critical security testing workflows into a single intelligent interface. Instead of switching between dozens of terminal tools, security analysts can launch assessments, monitor real-time progress, and receive AI-guided remediation advice — all in one place.

**Key differentiators:**
- 🤖 **Built-in AI Chat** — answers CVE, OWASP, attack technique questions instantly
- 📡 **Live Threat Intel** — Wikipedia + DuckDuckGo search integrated
- 🔊 **Voice Feedback** — gTTS-powered audio output (India English)
- 📊 **Risk Visualization** — threat graphs, severity ratings, port intelligence DB
- ⚡ **Real-time Progress** — scan status with percentage and elapsed time per tool
- 📄 **Auto Report** — downloadable VAPT report per assessment session

---

## 🛠️ Tools & Capabilities

### 🔍 Network VAPT — 10 Tools

| Tool | Command Used | What It Does |
|------|-------------|--------------|
| **Port Scanner (Quick)** | `nmap -Pn -T4 -F --open` | Fast top-100 port discovery |
| **Port Scanner (Full)** | `nmap -Pn -T4 -sV -sC -A` | Service + version + script detection |
| **Vulnerability Scan** | `nmap --script vuln -sV` | CVE detection via NSE scripts |
| **OS Detection** | `nmap -O -sV` | Remote OS fingerprinting |
| **UDP Scan** | `nmap -sU --top-ports 50` | Top 50 UDP service discovery |
| **Firewall Detection** | `nmap -sA + firewall-bypass` | ACK scan + bypass testing |
| **Banner Grab** | `nmap --script banner` | Service version banners |
| **ARP Scan** | `nmap -sn <subnet>` | Local network host discovery |
| **SMB Enumeration** | `smb-enum-shares + enum4linux` | Shares, users, MS17-010 EternalBlue |
| **DNS Zone Transfer** | `dig axfr + nmap dns-zone-transfer` | Misconfigured DNS exploitation |

### 🌐 Web VAPT — 12 Tools

| Tool | Engine | What It Does |
|------|--------|--------------|
| **HTTP Header Audit** | `curl -sI` | Detects missing CSP, HSTS, X-Frame-Options |
| **SSL/TLS Analysis** | `openssl + nmap ssl-*` | Heartbleed, POODLE, weak ciphers |
| **WAF Detection** | `wafw00f + nmap http-waf-*` | Identifies WAF vendor + bypass potential |
| **Nikto Web Scan** | `nikto` | 6700+ web vulnerability signatures |
| **Directory Enumeration** | `gobuster / dirb` | Wordlist-based hidden path discovery |
| **Admin Panel Finder** | Custom crawler | 20+ admin paths tested |
| **CMS Detection** | `whatweb + wpscan` | WordPress, Joomla, Drupal fingerprinting |
| **CORS Check** | `curl + nmap http-cors` | Cross-origin misconfiguration detection |
| **SQL Injection** | `sqlmap --batch --forms` | Automated SQLi with form crawling |
| **XSS Scanner** | `nmap http-xss-* + payloads` | Reflected, Stored, DOM-based XSS |
| **HTTP Methods** | `curl -X <METHOD>` | PUT/DELETE/TRACE/CONNECT exposure |
| **Subdomain Enum** | DNS bruteforce | 40+ common subdomains tested |

### 🏗️ Infrastructure VAPT — 8 Tools

| Tool | What It Checks |
|------|---------------|
| **SSH Audit** | Weak algorithms, root login, auth methods |
| **FTP Check** | Anonymous login, bounce attack, CVE-2010-4221 |
| **RDP Check** | BlueKeep CVE-2019-0708, MS12-020, NLA config |
| **Database Exposure** | MySQL 3306, PostgreSQL 5432, MongoDB 27017, Redis 6379, Elasticsearch 9200 |
| **Docker / K8s Check** | Docker API port 2375, Kubelet 10250, AWS metadata |
| **CVE Scan** | Full `nmap --script vuln + exploit` suite |
| **WinRM Check** | Windows Remote Management HTTP/HTTPS |
| **SNMP Audit** | SNMPv1/v2 bruteforce + interface/process enumeration |

### 🔬 Nuclei Scanner — 6 Scan Types

| Type | Templates | Severity |
|------|-----------|----------|
| Full Scan | All templates | All severities |
| CVE Scan | `cves/` | Critical, High |
| Misconfiguration | `misconfiguration/ + exposed-panels/` | All |
| Tech Detection | `technologies/` | Info |
| Critical/High | All templates | Critical + High only |
| Network Scan | `network/` | All |

### 🌐 Recon — 8 Tools
`WHOIS` · `DNS (A/MX/NS/TXT/CNAME/SOA/AAAA)` · `IP Geolocation` · `Ping` · `Traceroute` · `Local Network Scan` · `My IP` · `System Info`

---

## 🧠 Intelligence Databases

### Port Knowledge Base — 50+ Ports
Every open port cross-referenced for risk:

```
PORT  6379  →  Redis
Severity  :  CRITICAL
Risk      :  No auth by default. Full DB read/write/RCE possible.
Fix       :  requirepass in redis.conf. Bind to 127.0.0.1 only.
```

### CVE Vulnerability Database — 25+ Signatures

| CVE | Vulnerability | Severity |
|-----|--------------|----------|
| CVE-2017-0144 | EternalBlue / MS17-010 (WannaCry SMB) | 🔴 CRITICAL |
| CVE-2021-44228 | Log4Shell (Log4j RCE) | 🔴 CRITICAL |
| CVE-2019-0708 | BlueKeep (RDP RCE) | 🔴 CRITICAL |
| CVE-2014-0160 | Heartbleed (OpenSSL) | 🔴 CRITICAL |
| CVE-2021-34527 | PrintNightmare | 🔴 CRITICAL |
| CVE-2020-1472 | ZeroLogon (Netlogon) | 🔴 CRITICAL |
| CVE-2014-6271 | Shellshock (Bash RCE) | 🔴 CRITICAL |
| CVE-2014-3566 | POODLE (SSLv3) | 🟠 HIGH |
| — | FTP Anonymous Login | 🟠 HIGH |
| — | Missing HSTS Header | 🟡 MEDIUM |

---

## 🤖 AI Chat Assistant

No internet needed — built-in cybersecurity knowledge:

```
"What is SQL injection?"      → Attack types + examples + prevention
"Explain OWASP Top 10"        → All 10 with 2021 categories
"How to secure SSH?"          → 8-point hardening checklist
"What is Log4Shell?"          → CVE-2021-44228 full breakdown
"Explain BlueKeep"            → CVE-2019-0708 RDP analysis
"search Cloudflare WAF"       → Live Wikipedia/DuckDuckGo result
```

Topics: SQLi · XSS · SSRF · RCE · MITM · DDoS · Ransomware · Zero-day · OWASP · CIA Triad · CVSS · Encryption · TLS · Docker Security · K8s Hardening

---

## 🚀 Installation

```bash
# 1. Clone repository
git clone https://github.com/sreeharshavoleti-art/harsha-VAPT-suite.git
cd harsha-VAPT-suite

# 2. Install Python dependencies
pip install flask gtts requests psutil

# 3. Install security tools
sudo apt install -y nmap nikto gobuster dirb sqlmap whatweb
pip install wafw00f

# 4. Run HARSHA AI
python harsha_VAPT.py

# 5. Open browser
# http://localhost:5000
```

---

## 🏗️ Architecture

```
harsha-VAPT-suite/
│
├── harsha_VAPT.py              ← Core engine (2487 lines)
│   ├── /scan  endpoint         ← Tool execution handler
│   ├── /chat  endpoint         ← AI chat response
│   ├── /voice endpoint         ← gTTS audio output
│   ├── Scan Progress Tracker   ← Real-time threading
│   ├── Port Intelligence DB    ← 50+ ports with severity
│   ├── CVE Vulnerability DB    ← 25+ CVE signatures
│   ├── AI Chat Engine          ← Keyword + NLP responses
│   ├── Search Engine           ← Wikipedia + DuckDuckGo
│   └── Nuclei Integration      ← 6 template scan types
│
└── README.md
```

---

## ⚙️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.8+, Flask |
| Network Scanning | Nmap, enum4linux, snmpwalk |
| Web Testing | Nikto, SQLMap, Gobuster, wafw00f, whatweb |
| Vulnerability Scanning | Nuclei, Nmap NSE scripts |
| AI + Search | Wikipedia REST API, DuckDuckGo API |
| Voice | gTTS (Google Text-to-Speech) |
| System Monitoring | psutil, threading, subprocess |

---

## ⚠️ Legal Disclaimer

> **This tool is developed strictly for authorized security testing and educational purposes.**
> Scanning systems without explicit written permission is **illegal** under the
> Computer Fraud and Abuse Act (CFAA), IT Act 2000 (India), and other applicable laws.
> The author assumes **no liability** for unauthorized or illegal use of this software.
> **Always obtain proper authorization before conducting any security assessment.**

---

## 👤 Author

<table>
<tr>
<td align="center">
<br/>
<b>Voleti Sriharsha Vardhan Sharma</b>
<br/>
<i>IT Security Analyst | VAPT Engineer | Cybersecurity Researcher</i>
<br/><br/>

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0A66C2?style=for-the-badge&logo=linkedin)](https://linkedin.com/in/sreeharshavardhan-voleti-742249210/)
[![Email](https://img.shields.io/badge/Email-Contact-EA4335?style=for-the-badge&logo=gmail&logoColor=white)](mailto:sreeharsha.voleti@gmail.com)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-181717?style=for-the-badge&logo=github)](https://github.com/sreeharshavoleti-art)

<br/>

📍 Hyderabad, Telangana, India<br/>
🏢 IT Security Analyst — Fluentgrid Limited (2023–Present)<br/>
🎓 B.Tech Information Technology — Raghu Engineering College, AP<br/>
🎯 M.Tech CSIS Aspirant — IIIT Hyderabad 2026

</td>
</tr>
</table>

---

<div align="center">

**If this project helped you, please consider giving it a ⭐ Star!**

*"The best hackers think like attackers but act like defenders."*

**Built with ❤️ by Harsha | Hyderabad, India | 2025–2026**

</div>
