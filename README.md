<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=28&pause=1000&color=00FF41&center=true&vCenter=true&width=750&lines=HARSHA+AI+v10.1+Beta+%7C+VAPT+Suite+%F0%9F%9B%A1%EF%B8%8F;Attack+Chain+Engine+%7C+Kill+Chain+Mapping;Web+%7C+Network+%7C+Infrastructure+%7C+Cloud" alt="Typing SVG" />

<br/>

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-Web%20UI-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![Nmap](https://img.shields.io/badge/Nmap-Integrated-4CAF50?style=for-the-badge&logo=linux&logoColor=white)](https://nmap.org)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)
[![Tools](https://img.shields.io/badge/Tools-30%2B-E74C3C?style=for-the-badge&logo=hackthebox&logoColor=white)](https://github.com/sreeharshavoleti-art/harsha-VAPT-suite)
[![Lines](https://img.shields.io/badge/Lines%20of%20Code-3098-8E44AD?style=for-the-badge)](https://github.com/sreeharshavoleti-art/harsha-VAPT-suite)
[![Version](https://img.shields.io/badge/Version-10.1%20Beta-FF6B35?style=for-the-badge)](https://github.com/sreeharshavoleti-art/harsha-VAPT-suite)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-268BEE?style=for-the-badge&logo=kalilinux&logoColor=white)](https://kali.org)

<br/>

> **A comprehensive AI-powered VAPT framework with Attack Chain Engine, Kill Chain Mapping, and 3-audience reporting.**
> Built for security professionals. Covers Web, Network, Infrastructure & Cloud with 30+ tools and intelligent attack path analysis.

<br/>

[🚀 Quick Start](#-installation) · [⛓️ Attack Chain Engine](#️-attack-chain-engine--new-in-v101) · [🛠️ Tools](#️-tools--capabilities) · [📸 Screenshots](#-screenshots) · [👤 Author](#-author)

---

</div>

## 🆕 What's New in v10.1 Beta

| Feature | v10.0 | v10.1 Beta |
|---------|-------|------------|
| Lines of Code | 2,487 | **3,098** (+611) |
| File Size | 184 KB | **228 KB** |
| Attack Chain Engine | ❌ | ✅ **10 kill chains** |
| Kill Chain Mapping | ❌ | ✅ **MITRE ATT&CK style** |
| Business Impact in ₹ | ❌ | ✅ **INR cost estimates** |
| 3-Audience Reports | ❌ | ✅ **Executive + Technical + Compliance** |
| DPDP Act 2023 Compliance | ❌ | ✅ **India's new data law** |
| ISO27001 / PCI-DSS / SOC2 | ❌ | ✅ **All 4 frameworks** |
| Confidence Scoring | ❌ | ✅ **% match per chain** |

---

## ⛓️ Attack Chain Engine — New in v10.1

> **The most powerful feature of HARSHA AI** — automatically connects individual vulnerabilities into full attack paths, showing exactly how a real attacker would chain weaknesses together for maximum impact.

### How It Works

```
Scan Results → Port Analysis → Threat Correlation → Chain Matching → Kill Chain Report
     ↓               ↓               ↓                   ↓                ↓
 Open ports      CVE findings    Keyword match       50%+ confidence    Business impact
```
![image alt](https://github.com/sreeharshavoleti-art/harsha-VAPT-suite/blob/4cd922bc43c1a55847fa5fbd86009e0f2c7672fb/Kill%20Chain%20Analysis.png)
### 10 Attack Chains Detected

| # | Attack Chain | Kill Chain Phases | Severity | Cost Exposure |
|---|-------------|-------------------|----------|---------------|
| 1 | **FTP → Web Shell Upload** | Initial Access → Execution → Persistence | 🔴 CRITICAL | ₹8–25 Lakhs |
| 2 | **SQL Injection → Data Exfiltration** | Initial Access → Collection → Exfiltration | 🔴 CRITICAL | ₹15–50 Lakhs |
| 3 | **SSH Brute Force → Privilege Escalation** | Initial Access → PrivEsc → Impact | 🔴 CRITICAL | ₹10–30 Lakhs |
| 4 | **SSL/TLS Weakness → MITM Attack** | Recon → Credential Access → Collection | 🟠 HIGH | ₹5–15 Lakhs |
| 5 | **Exposed Database → Mass Data Theft** | Recon → Collection → Exfiltration | 🔴 CRITICAL | ₹20–75 Lakhs |
| 6 | **XSS → Session Hijacking** | Initial Access → Credential Access → Impact | 🟠 HIGH | ₹3–10 Lakhs |
| 7 | **SMB Exploit → Lateral Movement** | Initial Access → Lateral → Impact | 🔴 CRITICAL | ₹25–100 Lakhs |
| 8 | **CORS Misconfiguration → Account Takeover** | Initial Access → Credential Access | 🟠 HIGH | ₹2–8 Lakhs |
| 9 | **RDP Exposure → Ransomware** | Initial Access → Execution → Impact | 🔴 CRITICAL | ₹15–50 Lakhs |
| 10 | **Docker API → Container Escape** | Initial Access → Execution → PrivEsc | 🔴 CRITICAL | ₹10–40 Lakhs |

### Chain Confidence Scoring

Each chain gets a confidence percentage based on evidence found:

```
Chain: SQL Injection → Data Exfiltration
Confidence: 75%

Step 1 ✅ Web Application Exposed     [Port 80/443 open — CONFIRMED]
Step 2 ✅ SQL Injection Found          [SQLMap findings — CONFIRMED]
Step 3 ⚠️  Database Service Reachable  [Port 3306 not found — PARTIAL]

Impact: Full Database Extraction — attacker dumps all tables including
        user credentials, payment data, and PII.

Business Impact: Mass data breach. DPDP Act violation, lawsuits.
Cost Exposure:   ₹15–50 Lakhs
```

---

## 📊 3-Audience Report System

HARSHA AI v10.1 generates **three different reports** from a single scan — tailored for each audience:

### 👔 Executive Report
- Plain-language risk summary (no technical jargon)
- Business impact in Indian Rupees (₹)
- Top 5 risks ranked by financial exposure
- Go/No-go remediation recommendation

### 🔧 Technical Report
- Full port analysis with severity ratings
- CVE findings with CVSS scores
- Attack chain step-by-step breakdown
- Specific fix commands and configurations

### 📋 Compliance Report

| Framework | Coverage |
|-----------|----------|
| **ISO 27001** | A.9, A.10, A.13, A.14 controls mapped |
| **PCI-DSS** | Requirements 1, 2, 4, 6, 8 |
| **SOC 2** | CC6.1, CC6.2, CC6.3, CC6.6, CC6.7 |
| **DPDP Act 2023** | Section 8, 9 — India's new data protection law |

---


## 📸 Screenshots
Threat Graph
![image alt](https://github.com/sreeharshavoleti-art/harsha-VAPT-suite/blob/edb46cfca0b43cecd9510e12ccfc3a7168f89760/Threat%20Graph.png)

VAPT Report
![image alt](https://github.com/sreeharshavoleti-art/harsha-VAPT-suite/blob/edb46cfca0b43cecd9510e12ccfc3a7168f89760/VAPT.png)

Dashboard
![image alt](https://github.com/sreeharshavoleti-art/harsha-VAPT-suite/blob/edb46cfca0b43cecd9510e12ccfc3a7168f89760/dashboard.png)
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

### 🔬 Nuclei Scanner — 6 Types
Full · CVE · Misconfiguration · Tech Detection · Critical/High · Network

### 🌐 Recon — 8 Tools
`WHOIS` · `DNS` · `IP Geolocation` · `Ping` · `Traceroute` · `Network Scan` · `My IP` · `System Info`

---

## 🧠 Intelligence Databases

### Port Knowledge Base — 50+ Ports
### CVE Database — 25+ Signatures

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

---

## 🚀 Installation

```bash
# 1. Clone repository
git clone https://github.com/sreeharshavoleti-art/harsha-VAPT-suite.git
cd harsha-VAPT-suite

# 2. Install Python dependencies
pip install flask gtts requests psutil

# 3. Install security tools (Kali Linux recommended)
sudo apt install -y nmap nikto gobuster dirb sqlmap whatweb
pip install wafw00f

# 4. Run HARSHA AI v10.1 Beta
python "Harsha_VAPT_beta version_10.1.py"

# 5. Open browser → http://localhost:5000
```

---

## 🏗️ Architecture

```
harsha-VAPT-suite/
│
├── harsha_VAPT.py                    ← Stable v10.0 (2487 lines)
├── Harsha_VAPT_beta version_10.1.py  ← Beta v10.1 (3098 lines)
│   ├── /scan  endpoint               ← 30+ tool handlers
│   ├── /chat  endpoint               ← AI chat engine
│   ├── /voice endpoint               ← gTTS audio
│   ├── /report endpoint              ← 3-audience report
│   ├── Attack Chain Engine           ← 10 kill chains ← NEW
│   ├── Chain Confidence Scorer       ← % match analysis ← NEW
│   ├── 3-Audience Report Generator   ← Exec+Tech+Compliance ← NEW
│   ├── DPDP Act 2023 Mapper         ← India compliance ← NEW
│   ├── Port Intelligence DB          ← 50+ ports
│   ├── CVE Vulnerability DB          ← 25+ CVEs
│   ├── AI Chat Engine                ← Built-in knowledge
│   └── Wikipedia + DuckDuckGo Search ← Live intel
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
| Attack Chain Analysis | Custom rule engine (10 chains) |
| Compliance Mapping | ISO27001, PCI-DSS, SOC2, DPDP Act 2023 |
| AI + Search | Wikipedia REST API, DuckDuckGo API |
| Voice | gTTS (Google Text-to-Speech, India English) |
| Reporting | 3-audience JSON → HTML report generator |

---

## ⚠️ Legal Disclaimer

> **This tool is developed strictly for authorized security testing and educational purposes.**
> Scanning systems without explicit written permission is **illegal** under the
> Computer Fraud and Abuse Act (CFAA), IT Act 2000 (India), DPDP Act 2023, and other applicable laws.
> The author assumes **no liability** for unauthorized or illegal use.
> **Always obtain proper written authorization before any security assessment.**

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
 India<br/>
🏢 IT Security Analyst — Fluentgrid Limited (2023–Present)<br/>
🎓 B.Tech Information Technology — Raghu Engineering College, AP<br/>


</td>
</tr>
</table>

---

## 📌 Changelog

```
v10.1 Beta (Mar 2026)
+ Attack Chain Engine — 10 kill chains with confidence scoring
+ 3-Audience Report Generator (Executive / Technical / Compliance)
+ DPDP Act 2023 compliance mapping (India)
+ ISO27001, PCI-DSS, SOC2 control mapping
+ Business impact in INR (₹ lakh estimates per chain)
+ +611 lines of new code (2487 → 3098)

v10.0 (Feb 2026)
+ 30+ VAPT tools (Network, Web, Infra, Nuclei, Recon)
+ AI Chat Assistant with built-in security knowledge
+ Wikipedia + DuckDuckGo live search
+ Voice output (India English gTTS)
+ Real-time scan progress tracking
+ Port Intelligence DB (50+ ports)
+ CVE Vulnerability DB (25+ signatures)
```

---

<div align="center">

**If this project helped you, please give it a ⭐ Star!**

*"The best hackers think like attackers but act like defenders."*

**Built with ❤️ by Harsha | Hyderabad, India | 2025–2026**

</div>
