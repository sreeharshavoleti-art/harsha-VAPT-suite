from flask import Flask, request, jsonify, send_file, Response
from gtts import gTTS
import subprocess, datetime, socket, os, random, re, json

try:
    import requests as http_requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

app = Flask(__name__)
VOICE_FILE = "/tmp/harsha_voice.mp3"

# ═══════════════════════════════════════════════════════
#  SCAN STATUS TRACKING
# ═══════════════════════════════════════════════════════
import threading, time
scan_status = {
    "active": False,
    "tool": "",
    "tool_display": "",
    "target": "",
    "category": "",
    "phase": "idle",       # idle, initializing, scanning, analyzing, complete, error
    "percent": 0,
    "start_time": 0,
    "elapsed": 0,
    "message": "Ready",
    "history": []          # last 10 completed scans
}
scan_lock = threading.Lock()

def update_scan_status(**kwargs):
    with scan_lock:
        for k, v in kwargs.items():
            scan_status[k] = v
        if scan_status["start_time"] > 0:
            scan_status["elapsed"] = round(time.time() - scan_status["start_time"], 1)

# Tool display names for UI
TOOL_DISPLAY = {
    "nmap_quick":"Port Scanner (Quick)","nmap_full":"Port Scanner (Full)","nmap_vuln":"Vulnerability Scan",
    "nmap_os":"OS Detection","nmap_udp":"UDP Scan","nmap_firewall":"Firewall Detect",
    "nmap_banner":"Banner Grab","arp_scan":"ARP Scan","smb_enum":"SMB Enumeration",
    "snmp_enum":"SNMP Enumeration","dns_zone":"DNS Zone Transfer",
    "web_headers":"HTTP Header Audit","web_ssl":"SSL/TLS Analysis","web_waf":"WAF Detection",
    "web_nikto":"Nikto Web Scan","web_dirscan":"Directory Enumeration","web_admin":"Admin Panel Finder",
    "web_cms":"CMS Detection","web_cors":"CORS Check","web_sqli":"SQL Injection Test",
    "web_xss":"XSS Scanner","web_methods":"HTTP Methods","web_subdomain":"Subdomain Enumeration",
    "infra_ssh":"SSH Audit","infra_ftp":"FTP Check","infra_rdp":"RDP Check",
    "infra_db":"Database Exposure","infra_docker":"Docker/K8s Check","infra_cve":"CVE Scan",
    "infra_winrm":"WinRM Check","infra_snmp":"SNMP Audit",
    "whois":"WHOIS Lookup","dns":"DNS Records","ip_info":"IP Info","ping":"Ping",
    "traceroute":"Traceroute","network_scan":"Local Network Scan","my_ip":"My IP","system_info":"System Info",
    "weather":"Weather","nuclei_full":"Nuclei Full Scan","nuclei_cve":"Nuclei CVE Scan",
    "nuclei_misconfig":"Nuclei Misconfig Scan","nuclei_tech":"Nuclei Tech Detect",
    "nuclei_critical":"Nuclei Critical/High","nuclei_network":"Nuclei Network Scan"
}

# Estimated scan durations (seconds) for progress calculation
TOOL_DURATION = {
    "nmap_quick":20,"nmap_full":60,"nmap_vuln":120,"nmap_os":45,"nmap_udp":40,
    "nmap_firewall":25,"nmap_banner":20,"arp_scan":15,"smb_enum":20,"snmp_enum":20,
    "dns_zone":15,"web_headers":8,"web_ssl":12,"web_waf":10,"web_nikto":60,
    "web_dirscan":45,"web_admin":30,"web_cms":15,"web_cors":8,"web_sqli":20,
    "web_xss":25,"web_methods":10,"web_subdomain":30,"infra_ssh":20,"infra_ftp":15,
    "infra_rdp":15,"infra_db":25,"infra_docker":20,"infra_cve":120,"infra_winrm":15,
    "infra_snmp":25,"whois":10,"dns":12,"ip_info":5,"ping":10,"traceroute":15,
    "network_scan":20,"my_ip":5,"system_info":3,"weather":5,
    "nuclei_full":180,"nuclei_cve":180,"nuclei_misconfig":150,"nuclei_tech":60,
    "nuclei_critical":180,"nuclei_network":150
}

# ═══════════════════════════════════════════════════════
#  SEARCH ENGINES — Wikipedia + Google
# ═══════════════════════════════════════════════════════
def clean_search_query(raw):
    """Extract the core search terms from a natural language question."""
    q = raw.lower().strip().rstrip('?!.')
    # Remove conversational prefixes
    prefixes = [
        "can you tell me ", "could you tell me ", "please tell me ",
        "i want to know ", "i'd like to know ", "do you know ",
        "can you explain ", "please explain ", "explain me ",
        "what do you know about ", "tell me about ", "tell me ",
        "search for ", "look up ", "google ", "search ",
        "who is the ", "who is ", "who are the ", "who are ",
        "what is the ", "what is a ", "what is an ", "what is ",
        "what are the ", "what are ", "where is the ", "where is ",
        "when was the ", "when was ", "when did ", "when is ",
        "how does ", "how do ", "how is ", "how to ",
        "why is the ", "why is ", "why do ", "why are ",
        "define ", "meaning of ",
    ]
    for p in prefixes:
        if q.startswith(p):
            q = q[len(p):]
            break
    return q.strip()

def search_wikipedia(query, sentences=4):
    """Search Wikipedia and return a summary."""
    if not HAS_REQUESTS:
        return None
    try:
        search_url = "https://en.wikipedia.org/w/api.php"
        search_params = {
            "action": "query", "list": "search",
            "srsearch": query, "srlimit": 3,
            "format": "json", "utf8": 1
        }
        resp = http_requests.get(search_url, params=search_params, timeout=10)
        data = resp.json()
        results = data.get("query", {}).get("search", [])
        if not results:
            return None

        # Try each result until we get a good summary
        for result in results[:3]:
            title = result["title"]
            try:
                summary_url = "https://en.wikipedia.org/api/rest_v1/page/summary/" + title.replace(" ", "_")
                resp2 = http_requests.get(summary_url, timeout=10,
                    headers={"User-Agent": "HARSHA-AI/7.0 (Python; VAPT Suite)"})
                if resp2.status_code != 200:
                    continue
                sdata = resp2.json()
                extract = sdata.get("extract", "")
                if not extract or len(extract) < 30:
                    continue

                parts = extract.split(". ")
                if len(parts) > sentences:
                    extract = ". ".join(parts[:sentences]) + "."

                page_url = sdata.get("content_urls", {}).get("desktop", {}).get("page", "")
                return {"title": title, "summary": extract, "url": page_url}
            except Exception:
                continue
        return None
    except Exception as e:
        return None

def search_duckduckgo(query):
    """Search DuckDuckGo instant answers API."""
    if not HAS_REQUESTS:
        return None
    try:
        url = "https://api.duckduckgo.com/"
        params = {"q": query, "format": "json", "no_html": 1, "skip_disambig": 1}
        resp = http_requests.get(url, params=params, timeout=10,
            headers={"User-Agent": "HARSHA-AI/7.0 (Python; VAPT Suite)"})
        data = resp.json()

        # Priority 1: Abstract text (best quality)
        abstract = data.get("AbstractText", "")
        if abstract and len(abstract) > 40:
            return {"answer": abstract, "source": data.get("AbstractSource", "DuckDuckGo"),
                    "url": data.get("AbstractURL", "")}

        # Priority 2: Answer box
        answer = data.get("Answer", "")
        if answer and len(str(answer)) > 5:
            return {"answer": str(answer), "source": "DuckDuckGo", "url": ""}

        # Priority 3: Definition
        defn = data.get("Definition", "")
        if defn and len(defn) > 20:
            return {"answer": defn, "source": data.get("DefinitionSource", ""), "url": ""}

        # Priority 4: Infobox
        infobox = data.get("Infobox", {})
        if isinstance(infobox, dict) and infobox.get("content"):
            items = infobox["content"]
            info_parts = []
            for item in items[:6]:
                if isinstance(item, dict) and item.get("label") and item.get("value"):
                    info_parts.append(item["label"] + ": " + str(item["value"]))
            if info_parts:
                heading = data.get("Heading", query.title())
                return {"answer": heading + " — " + " | ".join(info_parts),
                        "source": data.get("AbstractSource", "DuckDuckGo"), "url": ""}

        # Priority 5: Related topics
        topics = data.get("RelatedTopics", [])
        if topics:
            results = []
            for t in topics[:3]:
                if isinstance(t, dict) and "Text" in t and len(t["Text"]) > 20:
                    results.append(t["Text"])
            if results:
                return {"answer": " | ".join(results), "source": "DuckDuckGo", "url": ""}

        return None
    except Exception:
        return None

def ai_search_answer(query):
    """Smart search: clean query, try multiple engines, multiple strategies."""
    raw_query = query
    clean_q = clean_search_query(query)

    if not clean_q or len(clean_q) < 2:
        return None

    # Strategy 1: Try Wikipedia with cleaned query
    wiki = search_wikipedia(clean_q)
    if wiki:
        return f"📖 {wiki['title']}: {wiki['summary']} (Source: Wikipedia)"

    # Strategy 2: Try DuckDuckGo with cleaned query
    ddg = search_duckduckgo(clean_q)
    if ddg:
        answer = f"🔍 {ddg['answer']}"
        if ddg.get('source') and ddg['source'] != 'DuckDuckGo':
            answer += f" (Source: {ddg['source']})"
        return answer

    # Strategy 3: Try with original query if different
    if clean_q != raw_query.lower().strip():
        wiki2 = search_wikipedia(raw_query)
        if wiki2:
            return f"📖 {wiki2['title']}: {wiki2['summary']} (Source: Wikipedia)"

        ddg2 = search_duckduckgo(raw_query)
        if ddg2:
            answer = f"🔍 {ddg2['answer']}"
            if ddg2.get('source'):
                answer += f" (Source: {ddg2['source']})"
            return answer

    # Strategy 4: Try reformulated queries
    reformulations = []
    q_lower = raw_query.lower()
    if "ceo" in q_lower:
        company = clean_q.replace("ceo of", "").replace("ceo", "").strip()
        if company:
            reformulations.append(company + " company")
            reformulations.append(company)
    elif "founder" in q_lower:
        entity = clean_q.replace("founder of", "").replace("founder", "").strip()
        if entity:
            reformulations.append(entity)
    elif "president" in q_lower or "prime minister" in q_lower:
        country = clean_q.replace("president of", "").replace("prime minister of", "").replace("president", "").replace("prime minister", "").strip()
        if country:
            reformulations.append(country)

    for rq in reformulations:
        wiki3 = search_wikipedia(rq)
        if wiki3:
            return f"📖 {wiki3['title']}: {wiki3['summary']} (Source: Wikipedia)"
        ddg3 = search_duckduckgo(rq + " " + ("CEO" if "ceo" in q_lower else ""))
        if ddg3:
            return f"🔍 {ddg3['answer']} (Source: {ddg3.get('source', '')})"

    return None

# ═══════════════════════════════════════════════════════
#  PORT KNOWLEDGE BASE
# ═══════════════════════════════════════════════════════
PORT_DB = {
    20:{"service":"FTP-DATA","severity":"HIGH","desc":"FTP data transfer port. Plain-text traffic sniffable.","fix":"Disable FTP. Use SFTP instead."},
    21:{"service":"FTP","severity":"HIGH","desc":"FTP control port. Credentials in plain text. Anonymous login risk.","fix":"Switch to SFTP. Check anonymous access with nmap --script ftp-anon"},
    22:{"service":"SSH","severity":"LOW","desc":"SSH encrypted remote access. Safe if properly hardened.","fix":"Disable root login. Use key-based auth. Keep updated."},
    23:{"service":"TELNET","severity":"CRITICAL","desc":"Telnet sends ALL data including passwords in plain text!","fix":"Disable Telnet immediately. Replace with SSH port 22."},
    25:{"service":"SMTP","severity":"MEDIUM","desc":"Mail server. Open relay risk if misconfigured.","fix":"Require SMTP auth. Use TLS. Restrict relay."},
    53:{"service":"DNS","severity":"MEDIUM","desc":"DNS service. Zone transfer attacks possible.","fix":"Disable zone transfers. Use DNSSEC."},
    80:{"service":"HTTP","severity":"MEDIUM","desc":"Web server without HTTPS encryption.","fix":"Redirect HTTP to HTTPS. Install SSL certificate."},
    110:{"service":"POP3","severity":"MEDIUM","desc":"Email retrieval in plain text.","fix":"Use POP3S port 995 with TLS."},
    111:{"service":"RPCBIND","severity":"HIGH","desc":"RPC portmapper. NFS attack vector.","fix":"Block port 111. Disable unused RPC services."},
    135:{"service":"MSRPC","severity":"HIGH","desc":"Microsoft RPC. Common Windows attack target.","fix":"Block from internet. Apply all Windows patches."},
    137:{"service":"NETBIOS-NS","severity":"HIGH","desc":"NetBIOS Name Service. Leaks system info.","fix":"Disable NetBIOS. Block 137-139 externally."},
    139:{"service":"NETBIOS","severity":"HIGH","desc":"NetBIOS Session. Legacy SMB protocol.","fix":"Use SMB over TCP port 445 only."},
    143:{"service":"IMAP","severity":"MEDIUM","desc":"Email access in plain text.","fix":"Use IMAPS port 993 with TLS."},
    161:{"service":"SNMP","severity":"HIGH","desc":"SNMP default community string public causes info leak.","fix":"Use SNMPv3 with auth. Change community strings."},
    389:{"service":"LDAP","severity":"MEDIUM","desc":"LDAP directory. Can leak user info unauthenticated.","fix":"Use LDAPS port 636. Require authentication."},
    443:{"service":"HTTPS","severity":"LOW","desc":"HTTPS web server. Encrypted. Check SSL config.","fix":"Run ssl scan. Check for weak ciphers."},
    445:{"service":"SMB","severity":"CRITICAL","desc":"SMB target of EternalBlue WannaCry ransomware!","fix":"Disable SMBv1. Block 445 from internet. Patch MS17-010."},
    512:{"service":"REXEC","severity":"CRITICAL","desc":"Remote exec no encryption no auth.","fix":"Disable immediately. Replace with SSH."},
    513:{"service":"RLOGIN","severity":"CRITICAL","desc":"Remote login legacy no encryption.","fix":"Disable rlogin. Use SSH instead."},
    514:{"service":"RSH","severity":"HIGH","desc":"Remote shell with no authentication.","fix":"Disable RSH. Use SSH."},
    873:{"service":"RSYNC","severity":"HIGH","desc":"Rsync may allow unauthenticated file access.","fix":"Require auth. Restrict by IP."},
    1433:{"service":"MSSQL","severity":"HIGH","desc":"MS SQL Server exposed. Brute force risk.","fix":"Block from internet. Strong SA password."},
    1521:{"service":"ORACLE","severity":"HIGH","desc":"Oracle database exposed.","fix":"Block from internet. Apply Oracle patches."},
    2049:{"service":"NFS","severity":"HIGH","desc":"NFS can allow remote file access without auth.","fix":"Restrict exports. Use Kerberos."},
    2375:{"service":"DOCKER","severity":"CRITICAL","desc":"Docker API exposed! Full container/host compromise possible!","fix":"Never expose Docker API. Use TLS auth if needed."},
    2376:{"service":"DOCKER-TLS","severity":"HIGH","desc":"Docker API with TLS. Verify certs are strict.","fix":"Verify client cert required. Restrict by IP."},
    3000:{"service":"DEV-SERVER","severity":"MEDIUM","desc":"Development server exposed. May have debug mode enabled.","fix":"Block from internet. Never run dev servers in production."},
    3306:{"service":"MYSQL","severity":"HIGH","desc":"MySQL database exposed. Brute force risk.","fix":"Bind to 127.0.0.1. Block externally."},
    3389:{"service":"RDP","severity":"CRITICAL","desc":"RDP exposed! BlueKeep brute force ransomware risk!","fix":"Enable NLA. Block from internet. Use VPN."},
    4444:{"service":"BACKDOOR","severity":"CRITICAL","desc":"Port 4444 common Metasploit malware backdoor!","fix":"Investigate immediately. Check for compromise."},
    5432:{"service":"POSTGRESQL","severity":"HIGH","desc":"PostgreSQL exposed. Data breach risk.","fix":"Bind to localhost. Block externally."},
    5555:{"service":"ADB","severity":"CRITICAL","desc":"Android Debug Bridge exposed. Full device control!","fix":"Disable ADB over network. USB only."},
    5900:{"service":"VNC","severity":"HIGH","desc":"VNC remote desktop exposed.","fix":"Add VNC password. Restrict by IP. Use SSH tunnel."},
    5985:{"service":"WINRM-HTTP","severity":"HIGH","desc":"Windows Remote Management over HTTP.","fix":"Use HTTPS WinRM. Restrict by IP. Require auth."},
    5986:{"service":"WINRM-HTTPS","severity":"MEDIUM","desc":"Windows Remote Management over HTTPS.","fix":"Restrict by IP. Require strong credentials."},
    6379:{"service":"REDIS","severity":"CRITICAL","desc":"Redis no auth by default! Full RCE possible!","fix":"Add Redis password. Bind to 127.0.0.1."},
    7001:{"service":"WEBLOGIC","severity":"HIGH","desc":"Oracle WebLogic server. Multiple critical CVEs.","fix":"Apply all patches. Restrict admin console access."},
    8080:{"service":"HTTP-ALT","severity":"MEDIUM","desc":"Alternate HTTP. Check for admin panels.","fix":"Secure web app. Use HTTPS."},
    8443:{"service":"HTTPS-ALT","severity":"LOW","desc":"Alternate HTTPS port.","fix":"Ensure strong TLS config."},
    8888:{"service":"JUPYTER","severity":"HIGH","desc":"Jupyter Notebook often on this port. RCE if exposed!","fix":"Add auth. Never expose Jupyter publicly."},
    9000:{"service":"PHP-FPM","severity":"HIGH","desc":"PHP-FPM exposed. Remote code execution risk.","fix":"Bind to Unix socket or 127.0.0.1 only."},
    9090:{"service":"PROMETHEUS","severity":"MEDIUM","desc":"Prometheus metrics exposed. Leaks internal info.","fix":"Restrict access. Add auth to Prometheus."},
    9200:{"service":"ELASTICSEARCH","severity":"CRITICAL","desc":"Elasticsearch no auth by default! All data readable!","fix":"Enable security. Bind to localhost."},
    10250:{"service":"KUBELET","severity":"CRITICAL","desc":"Kubernetes Kubelet API exposed! Cluster compromise!","fix":"Restrict kubelet API. Enable auth. Use firewall."},
    27017:{"service":"MONGODB","severity":"CRITICAL","desc":"MongoDB no auth by default! Full DB access!","fix":"Enable MongoDB auth. Bind to 127.0.0.1."},
}

VULN_DB = {
    "ms17-010":{"name":"EternalBlue MS17-010","severity":"CRITICAL","desc":"RCE via SMBv1 used by WannaCry ransomware.","fix":"Apply MS17-010 patch. Disable SMBv1. Block ports 445 and 139."},
    "eternalblue":{"name":"EternalBlue","severity":"CRITICAL","desc":"NSA exploit unauthenticated RCE via SMB.","fix":"Patch MS17-010. Disable SMBv1. Block inbound SMB."},
    "ms08-067":{"name":"MS08-067 NetAPI","severity":"CRITICAL","desc":"RCE in Windows Server exploited by Conficker worm.","fix":"Apply MS08-067 patch. Block port 445. Upgrade Windows."},
    "bluekeep":{"name":"BlueKeep CVE-2019-0708","severity":"CRITICAL","desc":"Wormable RDP RCE on Windows 7 and 2008.","fix":"Patch immediately. Enable NLA. Block RDP from internet."},
    "heartbleed":{"name":"Heartbleed CVE-2014-0160","severity":"CRITICAL","desc":"OpenSSL bug leaking server memory keys and passwords.","fix":"Upgrade OpenSSL. Reissue certificates. Reset passwords."},
    "shellshock":{"name":"Shellshock CVE-2014-6271","severity":"CRITICAL","desc":"Bash RCE via HTTP headers or CGI scripts.","fix":"Update Bash. Disable CGI. Use WAF."},
    "log4shell":{"name":"Log4Shell CVE-2021-44228","severity":"CRITICAL","desc":"Log4j RCE via JNDI injection in log messages.","fix":"Update Log4j to 2.17.1+. Disable JNDI lookup. Apply patches."},
    "printnightmare":{"name":"PrintNightmare CVE-2021-34527","severity":"CRITICAL","desc":"Windows Print Spooler RCE and local privilege escalation.","fix":"Disable Print Spooler on servers. Apply KB5004945 patch."},
    "zerologon":{"name":"ZeroLogon CVE-2020-1472","severity":"CRITICAL","desc":"Netlogon allows domain admin takeover with empty password.","fix":"Apply August 2020 Windows patches. Enable secure channel."},
    "ftp-anon":{"name":"FTP Anonymous Login","severity":"HIGH","desc":"FTP allows anonymous access without credentials.","fix":"Disable anonymous FTP. Use SFTP. Restrict by IP."},
    "ssl-poodle":{"name":"POODLE CVE-2014-3566","severity":"HIGH","desc":"SSLv3 CBC allows MITM traffic decryption.","fix":"Disable SSLv3. Use TLS 1.2 and 1.3 only."},
    "http-slowloris":{"name":"Slowloris DoS","severity":"HIGH","desc":"Server vulnerable to slow partial HTTP request DoS.","fix":"Set connection timeouts. Use Nginx. Deploy WAF."},
    "smb-vuln":{"name":"SMB Vulnerability","severity":"HIGH","desc":"SMB service has known vulnerabilities detected.","fix":"Disable SMBv1. Enable SMB signing. Apply patches."},
    "ssl-drown":{"name":"DROWN CVE-2016-0800","severity":"HIGH","desc":"SSLv2 support allows decryption of modern TLS.","fix":"Disable SSLv2. Upgrade OpenSSL."},
    "self-signed":{"name":"Self-Signed Certificate","severity":"MEDIUM","desc":"Self-signed cert means users cannot verify server identity.","fix":"Use free certificate from Lets Encrypt with certbot."},
    "ssl-beast":{"name":"BEAST Attack","severity":"MEDIUM","desc":"TLS 1.0 CBC allows HTTPS cookie decryption.","fix":"Upgrade to TLS 1.2 or 1.3. Use AEAD ciphers."},
    "x-frame-options":{"name":"Missing X-Frame-Options","severity":"MEDIUM","desc":"Clickjacking attacks possible without this header.","fix":"Add header: X-Frame-Options: SAMEORIGIN"},
    "content-security-policy":{"name":"Missing CSP Header","severity":"MEDIUM","desc":"No Content-Security-Policy header. XSS attacks enabled.","fix":"Add header: Content-Security-Policy: default-src self"},
    "strict-transport-security":{"name":"Missing HSTS","severity":"MEDIUM","desc":"No HSTS header. HTTP downgrade attacks possible.","fix":"Add header: Strict-Transport-Security: max-age=31536000"},
    "x-xss-protection":{"name":"Missing X-XSS-Protection","severity":"LOW","desc":"XSS protection header not configured.","fix":"Add header: X-XSS-Protection: 1; mode=block"},
    "x-content-type-options":{"name":"Missing X-Content-Type-Options","severity":"LOW","desc":"MIME sniffing not disabled.","fix":"Add header: X-Content-Type-Options: nosniff"},
}

def parse_open_ports(output):
    ports = []
    for m in re.finditer(r"(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?", output):
        pnum = int(m.group(1)); proto = m.group(2)
        service = m.group(3); version = (m.group(4) or "").strip()
        info = PORT_DB.get(pnum, {"service":service.upper(),"severity":"MEDIUM",
            "desc":"Port "+str(pnum)+" is open and accessible.",
            "fix":"Verify if port "+str(pnum)+" needs to be publicly accessible."})
        ports.append({"port":pnum,"proto":proto,"service":info["service"],
                      "severity":info["severity"],"desc":info["desc"],
                      "fix":info["fix"],"version":version})
    return ports

def parse_vuln_threats(output, tool_type="nmap"):
    threats, out_lower = [], output.lower()
    for key, t in VULN_DB.items():
        if key in out_lower: threats.append(dict(t))
    if "anonymous" in out_lower and "ftp" in out_lower:
        t = dict(VULN_DB["ftp-anon"])
        if not any(x["name"]==t["name"] for x in threats): threats.append(t)
    if tool_type == "headers":
        for hk in ["x-frame-options","content-security-policy","x-xss-protection","strict-transport-security","x-content-type-options"]:
            if hk not in out_lower:
                t = dict(VULN_DB[hk])
                if not any(x["name"]==t["name"] for x in threats): threats.append(t)
    if tool_type == "ssl" and ("self signed" in out_lower or "self-signed" in out_lower):
        t = dict(VULN_DB["self-signed"])
        if not any(x["name"]==t["name"] for x in threats): threats.append(t)
    order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
    threats.sort(key=lambda x: order.get(x["severity"],3))
    seen, unique = set(), []
    for t in threats:
        if t["name"] not in seen: seen.add(t["name"]); unique.append(t)
    return unique

def run_cmd(cmd, timeout=90):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired: return "Scan timed out."
    except Exception as e: return "Error: " + str(e)

def clean(t):
    return t.strip().replace("https://","").replace("http://","").split("/")[0]

# ═══════════════════════════════════════════════════════
#  NETWORK VAPT TOOLS
# ═══════════════════════════════════════════════════════
def nmap_quick(t):      return run_cmd("nmap -Pn -T4 -F --open " + clean(t), 60)
def nmap_full(t):       return run_cmd("nmap -Pn -T4 -sV -sC -A " + clean(t), 180)
def nmap_vuln(t):       return run_cmd("nmap -Pn --script vuln -sV -T4 " + clean(t), 180)
def nmap_os(t):         return run_cmd("nmap -Pn -O -sV " + clean(t), 90)
def nmap_udp(t):        return run_cmd("nmap -Pn -sU -T4 --top-ports 50 " + clean(t), 120)
def nmap_firewall(t):   return run_cmd("nmap -Pn -sA -T4 " + clean(t) + " && nmap -Pn --script firewall-bypass " + clean(t), 90)
def nmap_banner(t):     return run_cmd("nmap -Pn --script banner -sV " + clean(t), 90)
def nmap_arp():
    local = run_cmd("hostname -I").strip().split()[0]
    subnet = ".".join(local.split(".")[:3]) + ".0/24"
    return run_cmd("nmap -sn " + subnet + " --send-eth 2>/dev/null || nmap -sn " + subnet, 60)

def smb_enum(t):
    out = run_cmd("nmap -Pn --script smb-enum-shares,smb-enum-users,smb-security-mode,smb-vuln-ms17-010,smb2-security-mode " + clean(t), 90)
    out += "\n\n" + run_cmd("enum4linux -a " + clean(t) + " 2>/dev/null | head -100", 60)
    return out

def snmp_enum(t):
    out = run_cmd("nmap -Pn -sU -p 161 --script snmp-info,snmp-sysdescr,snmp-interfaces " + clean(t), 60)
    out += "\n\n" + run_cmd("snmpwalk -v2c -c public " + clean(t) + " 2>/dev/null | head -50", 30)
    return out

def dns_zone_transfer(t):
    domain = clean(t)
    ns_out = run_cmd("dig " + domain + " NS +short", 10)
    result = "NS Records:\n" + ns_out + "\n\nZone Transfer Attempts:\n"
    for ns in ns_out.strip().split("\n"):
        ns = ns.strip().rstrip(".")
        if ns: result += run_cmd("dig axfr " + domain + " @" + ns, 15) + "\n"
    result += "\n" + run_cmd("nmap -Pn --script dns-zone-transfer --script-args dns-zone-transfer.domain=" + domain + " " + clean(t), 30)
    return result

# ═══════════════════════════════════════════════════════
#  WEB VAPT TOOLS
# ═══════════════════════════════════════════════════════
def web_headers(t):
    url = t if t.startswith("http") else "https://" + t
    res = run_cmd("curl -sI --max-time 10 " + url, 15)
    missing = [h for h in ["X-Frame-Options","X-XSS-Protection","Strict-Transport-Security","Content-Security-Policy","X-Content-Type-Options"] if h.lower() not in res.lower()]
    if missing: res += "\n\nMISSING SECURITY HEADERS:\n" + "\n".join("  MISSING: " + h for h in missing)
    else: res += "\n\nAll security headers present!"
    return res

def web_ssl(t):
    c = clean(t)
    r = run_cmd("echo | openssl s_client -connect " + c + ":443 -servername " + c + " 2>/dev/null | openssl x509 -noout -dates -subject -issuer 2>/dev/null", 15)
    r += "\n\n" + run_cmd("nmap -Pn --script ssl-enum-ciphers,ssl-poodle,ssl-dh-params,ssl-heartbleed -p 443 " + c, 60)
    return r or "No SSL certificate found."

def web_waf(t):
    url = t if t.startswith("http") else "https://" + t
    r = run_cmd("wafw00f " + url + " 2>/dev/null", 30)
    if "not installed" in r.lower() or not r:
        r = run_cmd("nmap -Pn --script http-waf-detect,http-waf-fingerprint " + clean(t), 60)
    return r or "WAF detection requires wafw00f: pip install wafw00f"

def web_nikto(t):
    url = t if t.startswith("http") else "https://" + t
    return run_cmd("nikto -h " + url + " -maxtime 120 2>/dev/null", 130)

def web_dirscan(t):
    url = t if t.startswith("http") else "https://" + t
    if run_cmd("which gobuster").strip():
        return run_cmd("gobuster dir -u " + url + " -w /usr/share/wordlists/dirb/common.txt -t 30 -q 2>/dev/null", 120)
    return run_cmd("dirb " + url + " /usr/share/wordlists/dirb/common.txt -S 2>/dev/null", 120)

def web_admin_finder(t):
    url = t if t.startswith("http") else "https://" + t
    admin_paths = ["/admin","/admin/login","/administrator","/wp-admin","/wp-login.php",
                   "/phpmyadmin","/pma","/cpanel","/webmin","/manager/html",
                   "/admin.php","/login.php","/dashboard","/panel","/control",
                   "/backend","/cms","/portal","/system","/manage"]
    found = []
    for path in admin_paths:
        code = run_cmd("curl -so /dev/null -w '%{http_code}' --max-time 5 " + url + path, 8)
        if code in ["200","301","302","403"]: found.append("[" + code + "] " + url + path)
    return "\n".join(found) if found else "No admin panels found at common paths."

def web_cms(t):
    url = t if t.startswith("http") else "https://" + t
    r = run_cmd("whatweb -v " + url + " 2>/dev/null", 30)
    wpscan = run_cmd("which wpscan", 5)
    if wpscan.strip() and ("wordpress" in r.lower() or "wp-" in r.lower()):
        r += "\n\nWordPress Detected - Running WPScan:\n"
        r += run_cmd("wpscan --url " + url + " --no-update 2>/dev/null | head -60", 60)
    return r or "WhatWeb not installed: sudo apt install whatweb"

def web_cors(t):
    url = t if t.startswith("http") else "https://" + t
    r = run_cmd("curl -sI -H 'Origin: https://evil.com' --max-time 10 " + url, 15)
    r += "\n\n" + run_cmd("nmap -Pn --script http-cors " + clean(t), 30)
    issues = []
    if "access-control-allow-origin: *" in r.lower(): issues.append("CRITICAL: CORS allows ALL origins (*) - Any website can read responses!")
    if "access-control-allow-credentials: true" in r.lower(): issues.append("HIGH: CORS allows credentials - Session hijacking possible!")
    if "evil.com" in r.lower(): issues.append("HIGH: Server reflects attacker origin - CORS misconfiguration!")
    if issues: r += "\n\nCORS VULNERABILITIES FOUND:\n" + "\n".join("  " + i for i in issues)
    else: r += "\n\nNo obvious CORS misconfigurations detected."
    return r

def web_sqli(t):
    url = t if t.startswith("http") else "https://" + t
    r = run_cmd("which sqlmap", 5)
    if r.strip():
        return run_cmd("sqlmap -u " + url + " --batch --level=1 --risk=1 --forms --crawl=1 --random-agent 2>/dev/null | tail -40", 120)
    return "SQLMap not installed. Install: sudo apt install sqlmap\nManual test: Add \' to URL parameters and check for SQL errors."

def web_xss(t):
    url = t if t.startswith("http") else "https://" + t
    r = run_cmd("nmap -Pn --script http-stored-xss,http-dombased-xss,http-xssed " + clean(t), 60)
    r += "\n\n" + run_cmd("curl -sk --max-time 10 '" + url + "?q=<script>alert(1)</script>' | grep -i 'script' | head -5", 15)
    r += "\n\nManual XSS Test Payloads:\n"
    r += "  Basic: <script>alert('XSS')</script>\n"
    r += "  Image: <img src=x onerror=alert(1)>\n"
    r += "  SVG: <svg onload=alert(1)>\n"
    r += "  URL Encode: %3Cscript%3Ealert(1)%3C/script%3E"
    return r

def web_methods(t):
    url = t if t.startswith("http") else "https://" + t
    methods = ["GET","POST","PUT","DELETE","PATCH","OPTIONS","HEAD","TRACE","CONNECT"]
    results = []
    for m in methods:
        code = run_cmd("curl -so /dev/null -w '%{http_code}' -X " + m + " --max-time 5 " + url, 8)
        danger = " [DANGEROUS!]" if m in ["PUT","DELETE","TRACE","CONNECT"] and code not in ["404","405","403"] else ""
        results.append("[" + code + "] " + m + danger)
    return "HTTP Methods Test for " + url + ":\n" + "\n".join(results)

def web_subdomain(t):
    subs = ["www","mail","ftp","api","admin","test","dev","staging","blog","shop","vpn","remote","portal","app","beta","cdn","login","secure","dashboard","support","docs","auth","api2","m","mobile","static","assets","media","files","old","new","backup","db","database"]
    found = []
    for s in subs:
        full = s + "." + clean(t)
        try:
            ip = socket.gethostbyname(full)
            found.append("FOUND: " + full + " -> " + ip)
        except: pass
    return "\n".join(found) or "No common subdomains found."

# ═══════════════════════════════════════════════════════
#  INFRASTRUCTURE VAPT TOOLS
# ═══════════════════════════════════════════════════════
def infra_ssh_audit(t):
    r = run_cmd("nmap -Pn --script ssh-auth-methods,ssh-hostkey,ssh2-enum-algos -p 22 " + clean(t), 60)
    r += "\n\n" + run_cmd("ssh-audit " + clean(t) + " 2>/dev/null | head -50", 30)
    return r

def infra_ftp(t):
    r = run_cmd("nmap -Pn --script ftp-anon,ftp-bounce,ftp-syst,ftp-vuln-cve2010-4221 -p 21 " + clean(t), 60)
    anon_test = run_cmd("curl -sk --max-time 5 ftp://" + clean(t) + "/ 2>&1", 8)
    if "Permission denied" not in anon_test and anon_test.strip():
        r += "\n\nANONYMOUS FTP ACCESS CONFIRMED:\n" + anon_test[:500]
    return r

def infra_rdp(t):
    r = run_cmd("nmap -Pn --script rdp-enum-encryption,rdp-vuln-ms12-020,rdp-vuln-ms16-068 -p 3389 " + clean(t), 60)
    r += "\n\n" + run_cmd("nmap -Pn --script rdp-enum-encryption -p 3389 " + clean(t), 30)
    return r

def infra_db_check(t):
    results = []
    mysql_r = run_cmd("nmap -Pn --script mysql-info,mysql-databases,mysql-empty-password -p 3306 " + clean(t), 30)
    if "open" in mysql_r: results.append("=== MYSQL (3306) ===\n" + mysql_r)
    pg_r = run_cmd("nmap -Pn --script pgsql-brute -p 5432 " + clean(t), 30)
    if "open" in pg_r: results.append("=== POSTGRESQL (5432) ===\n" + pg_r)
    mongo_r = run_cmd("nmap -Pn --script mongodb-info,mongodb-databases -p 27017 " + clean(t), 30)
    if "open" in mongo_r: results.append("=== MONGODB (27017) ===\n" + mongo_r)
    redis_r = run_cmd("nmap -Pn --script redis-info -p 6379 " + clean(t), 30)
    if "open" in redis_r: results.append("=== REDIS (6379) ===\n" + redis_r)
    es_r = run_cmd("curl -sk --max-time 5 http://" + clean(t) + ":9200/_cluster/health 2>/dev/null", 8)
    if es_r.strip(): results.append("=== ELASTICSEARCH (9200) OPEN ===\n" + es_r[:300])
    return "\n\n".join(results) if results else "No exposed databases found on common ports."

def infra_docker(t):
    results = []
    docker_r = run_cmd("curl -sk --max-time 5 http://" + clean(t) + ":2375/version 2>/dev/null", 8)
    if docker_r.strip(): results.append("CRITICAL: Docker API EXPOSED on port 2375!\n" + docker_r[:300])
    kube_r = run_cmd("curl -sk --max-time 5 https://" + clean(t) + ":6443/version 2>/dev/null", 8)
    if kube_r.strip() and "major" in kube_r: results.append("CRITICAL: Kubernetes API EXPOSED on port 6443!\n" + kube_r[:200])
    kubelet_r = run_cmd("curl -sk --max-time 5 https://" + clean(t) + ":10250/pods 2>/dev/null | head -5", 8)
    if kubelet_r.strip(): results.append("CRITICAL: Kubernetes Kubelet EXPOSED on port 10250!\n" + kubelet_r[:200])
    meta_r = run_cmd("curl -sk --max-time 3 http://169.254.169.254/latest/meta-data/ 2>/dev/null", 5)
    if meta_r.strip(): results.append("AWS Metadata Service accessible!\n" + meta_r[:200])
    r = run_cmd("nmap -Pn -p 2375,2376,6443,10250,10255,8080,9090 " + clean(t), 30)
    results.append("Port Scan (Docker/K8s ports):\n" + r)
    return "\n\n".join(results) if results else "No exposed Docker/Kubernetes services found."

def infra_cve_scan(t):
    r = run_cmd("nmap -Pn --script vuln -sV -T4 " + clean(t), 180)
    r += "\n\n" + run_cmd("nmap -Pn --script exploit " + clean(t), 60)
    return r

def infra_winrm(t):
    r = run_cmd("nmap -Pn --script http-auth-finder -p 5985,5986 " + clean(t), 30)
    r += "\n\n" + run_cmd("curl -sk --max-time 5 http://" + clean(t) + ":5985/wsman 2>/dev/null | head -5", 8)
    return r

def infra_snmp(t):
    return run_cmd("nmap -Pn -sU -p 161 --script snmp-brute,snmp-info,snmp-interfaces,snmp-netstat,snmp-processes " + clean(t), 60)

# ═══════════════════════════════════════════════════════
#  NUCLEI SCANNER
# ═══════════════════════════════════════════════════════
def nuclei_full(t):
    """Full Nuclei scan with all templates."""
    r = "═══ NUCLEI FULL SCAN — " + t + " ═══\n\n"
    out = run_cmd("nuclei -u " + clean(t) + " -silent -nc -timeout 15 -retries 1 -rl 50 2>&1", 300)
    if out.strip():
        r += out
    else:
        r += "No vulnerabilities found by Nuclei, or Nuclei is not installed.\n"
        r += "Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n"
        r += "Or: apt install nuclei\n"
    return r

def nuclei_cve(t):
    """Nuclei CVE-specific scan."""
    r = "═══ NUCLEI CVE SCAN — " + t + " ═══\n\n"
    out = run_cmd("nuclei -u " + clean(t) + " -t cves/ -silent -nc -timeout 15 -severity critical,high -rl 50 2>&1", 300)
    if out.strip():
        r += out
    else:
        r += "No CVEs detected.\n"
        r += "Tip: Make sure Nuclei templates are updated: nuclei -update-templates\n"
    return r

def nuclei_misconfig(t):
    """Nuclei misconfiguration scan."""
    r = "═══ NUCLEI MISCONFIGURATION SCAN — " + t + " ═══\n\n"
    out = run_cmd("nuclei -u " + clean(t) + " -t misconfiguration/ -t exposed-panels/ -t exposures/ -silent -nc -timeout 15 -rl 50 2>&1", 240)
    if out.strip():
        r += out
    else:
        r += "No misconfigurations found.\n"
    return r

def nuclei_tech(t):
    """Nuclei technology detection."""
    r = "═══ NUCLEI TECHNOLOGY DETECTION — " + t + " ═══\n\n"
    out = run_cmd("nuclei -u " + clean(t) + " -t technologies/ -silent -nc -timeout 10 -rl 50 2>&1", 120)
    if out.strip():
        r += out
    else:
        r += "No technologies detected via Nuclei.\n"
    return r

def nuclei_critical(t):
    """Nuclei critical and high severity only."""
    r = "═══ NUCLEI CRITICAL/HIGH SCAN — " + t + " ═══\n\n"
    out = run_cmd("nuclei -u " + clean(t) + " -severity critical,high -silent -nc -timeout 15 -rl 50 2>&1", 300)
    if out.strip():
        r += out
    else:
        r += "No critical/high severity issues found.\n"
    return r

def nuclei_network(t):
    """Nuclei network-level scan."""
    r = "═══ NUCLEI NETWORK SCAN — " + t + " ═══\n\n"
    out = run_cmd("nuclei -u " + clean(t) + " -t network/ -silent -nc -timeout 15 -rl 30 2>&1", 240)
    if out.strip():
        r += out
    else:
        r += "No network-level issues found.\n"
    return r

def parse_nuclei_threats(output):
    """Parse Nuclei output into threat objects."""
    threats = []
    lines = output.split("\n")
    for line in lines:
        line = line.strip()
        if not line or line.startswith("═") or line.startswith("Tip:") or line.startswith("Install:") or line.startswith("No "):
            continue
        # Nuclei output format: [template-id] [protocol] [severity] target
        sev = "MEDIUM"
        if "[critical]" in line.lower(): sev = "CRITICAL"
        elif "[high]" in line.lower(): sev = "HIGH"
        elif "[medium]" in line.lower(): sev = "MEDIUM"
        elif "[low]" in line.lower(): sev = "LOW"
        elif "[info]" in line.lower(): sev = "LOW"

        # Extract template name
        name = line
        if "] " in line:
            parts = line.split("] ")
            if parts:
                name = parts[0].replace("[", "").strip()

        if len(name) > 3 and name != output[:20]:
            threats.append({
                "name": "Nuclei: " + name[:80],
                "severity": sev,
                "desc": line[:200],
                "fix": "Review finding and apply vendor-recommended patch or configuration fix."
            })
    return threats

# ═══════════════════════════════════════════════════════
#  RECON TOOLS
# ═══════════════════════════════════════════════════════
def do_whois(t):    return run_cmd("whois " + clean(t), 30)[:4000]
def do_dns(t):
    out = []
    for r in ["A","MX","NS","TXT","CNAME","SOA","AAAA"]:
        res = run_cmd("dig " + clean(t) + " " + r + " +short", 10)
        if res.strip(): out.append("-- " + r + " --\n" + res)
    return "\n\n".join(out) or "No DNS records found."
def do_ip_info(ip):
    try:
        import requests
        d = requests.get("http://ip-api.com/json/" + ip, timeout=5).json()
        if d.get("status") == "success":
            return "IP: "+str(d.get("query"))+"\nCountry: "+str(d.get("country"))+"\nCity: "+str(d.get("city"))+"\nISP: "+str(d.get("isp"))+"\nOrg: "+str(d.get("org"))+"\nTimezone: "+str(d.get("timezone"))+"\nAS: "+str(d.get("as"))
        return "IP lookup failed."
    except Exception as e: return str(e)
def do_ping(t):   return run_cmd("ping -c 4 " + clean(t), 15)
def do_trace(t):  return run_cmd("traceroute -m 15 " + clean(t) + " 2>/dev/null || tracepath " + clean(t), 30)
def do_netscan():
    local = run_cmd("hostname -I").strip().split()[0]
    subnet = ".".join(local.split(".")[:3]) + ".0/24"
    return run_cmd("nmap -sn " + subnet, 60)
def get_my_ip():
    local = run_cmd("hostname -I").strip()
    try:
        import requests; pub = requests.get("https://api.ipify.org", timeout=5).text.strip()
    except: pub = "Unavailable"
    return "Local IP: " + local + "\nPublic IP: " + pub
def get_sysinfo():
    try:
        import psutil
        cpu = psutil.cpu_percent(interval=1); ram = psutil.virtual_memory(); disk = psutil.disk_usage("/")
        bat = psutil.sensors_battery()
        b = "\nBattery: "+str(int(bat.percent))+"% "+("Charging" if bat.power_plugged else "Discharging") if bat else ""
        return "CPU: "+str(cpu)+"%\nRAM: "+str(ram.percent)+"% ("+str(round(ram.used/1e9,1))+"GB / "+str(round(ram.total/1e9,1))+"GB)\nDisk: "+str(disk.percent)+"%"+b
    except: return "Install psutil: pip install psutil"
def get_weather():
    try:
        import requests
        d = requests.get("https://api.open-meteo.com/v1/forecast?latitude=17.3850&longitude=78.4867&current_weather=true", timeout=5).json()["current_weather"]
        return "Location: Hyderabad\nTemp: "+str(d["temperature"])+"C\nWind: "+str(d["windspeed"])+" km/h"
    except: return "Weather unavailable."

def speak_generate(text):
    try: gTTS(text=text, lang="en", tld="co.in", slow=False).save(VOICE_FILE); return True
    except: return False

def get_greeting():
    h = datetime.datetime.now().hour
    if 5<=h<12: return "Good morning"
    elif 12<=h<17: return "Good afternoon"
    elif 17<=h<21: return "Good evening"
    return "Good night"

JOKES  = ["Why do hackers prefer dark mode? Light attracts script kiddies!","A SQL injection walks into a bar. The bartender drops all the tables.","There are 10 types of people: those who understand binary and those who dont."]
MOTIVES= ["Harsha every great hacker started by breaking their own stuff. Keep going!","Knowledge is the most powerful weapon in cybersecurity. Never stop learning Harsha!","The best hackers think like attackers but act like defenders. You have got this Harsha!"]

def chat_response(msg):
    m = msg.lower().strip()

    # --- Greetings ---
    if any(w in m for w in ["hello","hi","hey","yo","sup"]): return get_greeting() + " Harsha! HARSHA AI v7.0 online. Web + Network + Infra VAPT armed and ready!"
    if any(w in m for w in ["bye","goodbye","see you","later"]): return "Stay safe Harsha! HARSHA AI standing by. 🛡️"
    if any(w in m for w in ["thanks","thank you","thx"]): return "You're welcome Harsha! Always here to help with your security assessments."

    # --- Identity ---
    if any(p in m for p in ["who are you","your name","what are you","about you"]): return "I am HARSHA AI v7.0 — a comprehensive VAPT (Vulnerability Assessment & Penetration Testing) suite. I cover Web, Network, and Infrastructure security testing with 30+ integrated tools. Built by Harsha!"
    if any(p in m for p in ["who made you","who built","who created","developer"]): return "Built by Harsha! Full VAPT suite powered by Python, Nmap, and Kali Linux. Covering Web, Network, and Infrastructure penetration testing."

    # --- System/Utility ---
    if "time" in m: return "🕐 " + datetime.datetime.now().strftime("%I:%M:%S %p")
    if "date" in m or "today" in m: return "📅 " + datetime.datetime.now().strftime("%A, %B %d, %Y")
    if "weather" in m: return get_weather()
    if "system" in m or "cpu" in m or "ram" in m: return get_sysinfo()
    if "my ip" in m or "ip address" in m: return get_my_ip()
    if any(w in m for w in ["joke","funny","laugh"]): return random.choice(JOKES)
    if any(w in m for w in ["motivate","inspire","quote"]): return random.choice(MOTIVES)

    # --- VAPT Concepts ---
    if "what is vapt" in m or ("vapt" in m and "mean" in m) or ("vapt" in m and "explain" in m):
        return "VAPT stands for Vulnerability Assessment and Penetration Testing. It's a security testing approach that combines: 1) Vulnerability Assessment — automated scanning to identify known vulnerabilities, misconfigurations, and weaknesses. 2) Penetration Testing — manual/simulated attacks to exploit vulnerabilities and assess real-world impact. Together they provide a comprehensive security evaluation of systems, networks, and applications."

    if "what is penetration testing" in m or "what is pentest" in m:
        return "Penetration Testing (pentesting) is a simulated cyberattack against your system to find exploitable vulnerabilities. It involves: Reconnaissance → Scanning → Gaining Access → Maintaining Access → Reporting. Types include: Black Box (no prior knowledge), White Box (full knowledge), and Gray Box (partial knowledge)."

    if "vulnerability assessment" in m and ("what" in m or "explain" in m):
        return "Vulnerability Assessment is the process of identifying, quantifying, and prioritizing security vulnerabilities in a system. It uses automated scanners (like Nmap, Nikto, OpenVAS) to detect known CVEs, misconfigurations, default credentials, and missing patches. The output is a prioritized list of findings with severity ratings (Critical, High, Medium, Low)."

    if "owasp" in m and "top 10" in m:
        return "OWASP Top 10 (2021): 1) Broken Access Control 2) Cryptographic Failures 3) Injection (SQLi, XSS, Command) 4) Insecure Design 5) Security Misconfiguration 6) Vulnerable Components 7) Auth Failures 8) Software & Data Integrity Failures 9) Security Logging Failures 10) Server-Side Request Forgery (SSRF). Use our Web VAPT tools to test for most of these!"

    if "cvss" in m:
        return "CVSS (Common Vulnerability Scoring System) rates vulnerabilities 0-10: None (0), Low (0.1-3.9), Medium (4.0-6.9), High (7.0-8.9), Critical (9.0-10.0). It considers Attack Vector, Complexity, Privileges Required, User Interaction, Scope, and CIA impact (Confidentiality, Integrity, Availability)."

    if "cve" in m and ("what" in m or "explain" in m):
        return "CVE (Common Vulnerabilities and Exposures) is a standardized identifier for security vulnerabilities. Format: CVE-YEAR-NUMBER (e.g., CVE-2021-44228 = Log4Shell). CVEs are tracked by MITRE and listed in the National Vulnerability Database (NVD). Our Vuln Scan tool checks for known CVEs on target services."

    # --- SQL Injection ---
    if "sql injection" in m or "sqli" in m:
        if "prevent" in m or "fix" in m or "remediat" in m or "protect" in m:
            return "SQL Injection Prevention: 1) Use Parameterized Queries/Prepared Statements — never concatenate user input into SQL. 2) Use ORM frameworks (SQLAlchemy, Hibernate). 3) Input Validation — whitelist allowed characters. 4) Least Privilege — DB accounts should have minimal permissions. 5) WAF rules to detect SQLi patterns. 6) Regular security scanning with tools like our SQLMap checker."
        return "SQL Injection is a code injection attack that exploits vulnerabilities in an application's database layer. Attackers insert malicious SQL statements through user inputs to: dump databases, bypass authentication, modify/delete data, or even execute OS commands. Types: In-band (classic), Blind (Boolean/Time-based), and Out-of-band. Use our SQL Injection tool to test! Prevention: parameterized queries, input validation, WAFs."

    # --- XSS ---
    if "xss" in m or "cross site scripting" in m or "cross-site scripting" in m:
        if "prevent" in m or "fix" in m or "protect" in m:
            return "XSS Prevention: 1) Output Encoding — HTML-encode user data before rendering. 2) Content Security Policy (CSP) headers. 3) Input validation and sanitization. 4) Use frameworks with auto-escaping (React, Angular). 5) HTTPOnly and Secure cookie flags. 6) X-XSS-Protection header."
        return "Cross-Site Scripting (XSS) injects malicious scripts into web pages viewed by other users. Types: 1) Reflected XSS — payload in URL parameters, reflected by server. 2) Stored XSS — payload saved to database, served to all users (most dangerous). 3) DOM-based XSS — payload manipulates client-side DOM. Impact: session hijacking, credential theft, defacement, malware distribution. Use our XSS Scanner to test!"

    # --- Port Scanning ---
    if "port scan" in m or "nmap" in m:
        if "how to" in m or "use" in m:
            return "To scan ports: 1) Enter the target IP/domain in the target field. 2) Click 'Port Scanner' for a quick scan or 'Quick Top 100' for the most common ports. 3) Results appear in Terminal and the Ports tab shows a detailed breakdown with severity ratings. 4) Use 'Vuln Scan' for CVE detection on open services."
        return "Port scanning discovers open network services on a target. Open ports indicate running services that could be attack vectors. Common critical ports: 21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 53 (DNS), 80/443 (HTTP/S), 135/445 (SMB), 1433 (MSSQL), 3306 (MySQL), 3389 (RDP), 5432 (PostgreSQL), 6379 (Redis), 8080 (HTTP Proxy), 27017 (MongoDB). Our scanner identifies services, versions, and risk levels."

    # --- SSL/TLS ---
    if "ssl" in m or "tls" in m:
        if "prevent" in m or "fix" in m or "best practice" in m:
            return "SSL/TLS Best Practices: 1) Use TLS 1.2+ only (disable SSL 2.0/3.0, TLS 1.0/1.1). 2) Strong cipher suites (AES-256-GCM, ChaCha20). 3) Enable HSTS header. 4) Valid certificates from trusted CAs. 5) Enable OCSP Stapling. 6) Disable SSL compression (CRIME attack). 7) Forward Secrecy (ECDHE). 8) Regular certificate rotation."
        return "SSL/TLS secures communications between client and server through encryption. Common issues: expired/self-signed certificates, weak cipher suites, protocol downgrade attacks (POODLE, BEAST), Heartbleed (CVE-2014-0160). Use our SSL/TLS Check tool to audit a target's certificate chain, protocol versions, cipher strength, and known vulnerabilities."

    # --- CORS ---
    if "cors" in m:
        return "CORS (Cross-Origin Resource Sharing) controls which external domains can access your API. Misconfigured CORS can allow: unauthorized data access from malicious sites, credential theft, and cross-origin attacks. Dangerous: Access-Control-Allow-Origin: * with credentials. Fix: whitelist specific trusted origins, never reflect the Origin header blindly, restrict methods/headers. Use our CORS Check tool to test!"

    # --- WAF ---
    if "waf" in m:
        return "WAF (Web Application Firewall) filters and monitors HTTP traffic between web apps and the internet. It protects against SQLi, XSS, CSRF, file inclusion, and other OWASP Top 10 attacks. Popular WAFs: Cloudflare, AWS WAF, ModSecurity, Imperva, Akamai. Our WAF Detect tool identifies which WAF is protecting a target — useful for tailoring your testing approach."

    # --- SMB ---
    if "smb" in m:
        return "SMB (Server Message Block) is a file sharing protocol on ports 139/445. Security risks: EternalBlue (CVE-2017-0144, used in WannaCry), null session enumeration, anonymous access, SMBv1 vulnerabilities. Always disable SMBv1, enforce SMB signing, block ports 139/445 externally, use strong authentication. Our SMB Enum tool checks for anonymous access and enumerates shares."

    # --- SSH ---
    if "ssh" in m and ("what" in m or "explain" in m or "secure" in m or "audit" in m or "best" in m):
        return "SSH (Secure Shell) provides encrypted remote access on port 22. Best practices: 1) Disable password auth, use SSH keys. 2) Disable root login (PermitRootLogin no). 3) Use SSH key passphrases. 4) Restrict to specific users (AllowUsers). 5) Change default port. 6) Enable fail2ban for brute-force protection. 7) Use Ed25519 or RSA-4096 keys. 8) Disable X11 forwarding if unused. Our SSH Audit checks for weak configs."

    # --- RDP ---
    if "rdp" in m:
        return "RDP (Remote Desktop Protocol) on port 3389 enables remote Windows access. Risks: BlueKeep (CVE-2019-0708), brute-force attacks, man-in-the-middle. Security: 1) Enable Network Level Authentication (NLA). 2) Use VPN — never expose RDP to internet. 3) Strong passwords + account lockout. 4) Enable MFA. 5) Patch regularly. 6) Use RDP gateways. Our RDP Check tests for exposed services."

    # --- Docker/K8s ---
    if "docker" in m or "container" in m:
        return "Docker Security: 1) Never run containers as root. 2) Use official/trusted images. 3) Scan images for vulnerabilities (Trivy, Snyk). 4) Don't expose Docker socket (port 2375/2376). 5) Use read-only file systems. 6) Limit resources (CPU/memory). 7) Enable Content Trust. 8) Use network policies. Our Docker Check tests for exposed APIs and misconfigurations."

    if "kubernetes" in m or "k8s" in m:
        return "Kubernetes Security: 1) RBAC — least privilege access. 2) Network Policies to segment pods. 3) Pod Security Standards. 4) Don't expose API server publicly. 5) Encrypt etcd data. 6) Scan images before deployment. 7) Enable audit logging. 8) Use service mesh (Istio) for mTLS. 9) Regularly update components. Our K8s Check tests for exposed dashboards and APIs."

    # --- Network Security ---
    if "firewall" in m and ("what" in m or "explain" in m or "type" in m):
        return "Firewalls control network traffic based on rules. Types: 1) Packet Filtering — inspects headers (IP, port). 2) Stateful Inspection — tracks connection state. 3) Application-layer (WAF) — inspects content. 4) Next-Gen (NGFW) — combines all with IPS, deep packet inspection. Our Firewall Detect tool identifies if a target is behind a firewall and what type."

    if "dns" in m and ("what" in m or "explain" in m or "attack" in m):
        return "DNS (Domain Name System) translates domains to IPs. Security attacks: DNS spoofing/poisoning, DNS tunneling (data exfiltration), DNS amplification DDoS, zone transfer exploitation, subdomain takeover. Protection: DNSSEC, DoH/DoT, restrict zone transfers, monitor DNS logs. Use our DNS Lookup and Subdomain Enum tools for recon."

    # --- General Security Concepts ---
    if "brute force" in m:
        return "Brute Force attacks try all possible password combinations to gain access. Defense: 1) Account lockout after N failed attempts. 2) Rate limiting. 3) CAPTCHA after failed logins. 4) Multi-factor authentication (MFA). 5) Strong password policies. 6) fail2ban / IP blocking. 7) Monitor login logs for anomalies."

    if "phishing" in m:
        return "Phishing tricks users into revealing credentials or installing malware via fake emails/websites. Types: Spear phishing (targeted), Whaling (executives), Vishing (voice), Smishing (SMS). Defense: Email filtering, SPF/DKIM/DMARC, security awareness training, MFA, URL scanning, sandbox analysis."

    if "ransomware" in m:
        return "Ransomware encrypts files and demands payment for decryption. Defense: 1) Regular offline backups (3-2-1 rule). 2) Patch management. 3) Email filtering. 4) Network segmentation. 5) Endpoint Detection & Response (EDR). 6) Least privilege access. 7) Disable macros. 8) Incident response plan. Notable: WannaCry, NotPetya, REvil, LockBit."

    if "zero day" in m or "0day" in m or "0-day" in m:
        return "Zero-day vulnerabilities are unknown to the vendor with no patch available. Defense: 1) Defense in depth (multiple security layers). 2) Behavioral detection (EDR/XDR). 3) Network segmentation. 4) Application whitelisting. 5) Regular patching to reduce attack surface. 6) Threat intelligence feeds. 7) Bug bounty programs."

    if any(p in m for p in ["social engineering","social attack"]):
        return "Social Engineering manipulates people into revealing info or performing actions. Types: Phishing, Pretexting, Baiting, Tailgating, Quid Pro Quo, Watering Hole attacks. Defense: Security awareness training, verify identities, strict access policies, physical security, incident reporting culture."

    if "mitm" in m or "man in the middle" in m or "man-in-the-middle" in m:
        return "Man-in-the-Middle (MITM) attacks intercept communications between two parties. Types: ARP spoofing, DNS spoofing, SSL stripping, Wi-Fi eavesdropping. Defense: Use HTTPS/TLS everywhere, HSTS, certificate pinning, VPNs, ARP inspection, encrypted DNS (DoH/DoT). Our ARP Scan can detect potential MITM setups."

    if "ddos" in m or "dos attack" in m or "denial of service" in m:
        return "DDoS (Distributed Denial of Service) overwhelms targets with traffic. Types: Volumetric (UDP flood, DNS amp), Protocol (SYN flood, Ping of Death), Application-layer (HTTP flood, Slowloris). Defense: CDN/DDoS protection (Cloudflare, AWS Shield), rate limiting, SYN cookies, traffic analysis, redundant infrastructure."

    if "encryption" in m and ("what" in m or "explain" in m or "type" in m):
        return "Encryption protects data by converting it to unreadable form. Types: 1) Symmetric (AES-256, ChaCha20) — same key for encrypt/decrypt, fast. 2) Asymmetric (RSA, ECC) — public/private key pair, used for key exchange. 3) Hashing (SHA-256, bcrypt) — one-way, for passwords/integrity. Best practice: AES-256-GCM for data, RSA-4096/Ed25519 for keys, bcrypt/Argon2 for passwords."

    if ("cia" in m or "confidentiality" in m) and ("triad" in m or "security" in m or "integrity" in m):
        return "CIA Triad — the three pillars of information security: 1) Confidentiality — only authorized users access data (encryption, access controls). 2) Integrity — data is accurate and unaltered (hashing, digital signatures, checksums). 3) Availability — systems are accessible when needed (redundancy, backups, DDoS protection)."

    # --- Tool Help ---
    if "help" in m or "what can you do" in m or "features" in m:
        return "HARSHA AI v7.0 can help with: 🔍 Run 30+ VAPT scans (sidebar tools) | 📊 Risk Analysis & Threat Graphs | 💬 Ask me about any security concept — SQLi, XSS, CVEs, OWASP, encryption, network attacks, best practices | 📄 Generate VAPT reports | 🛡 Get remediation advice for any vulnerability. Try asking: 'What is SQL injection?', 'How to prevent XSS?', 'Explain OWASP Top 10', 'What is CVSS?'"

    if "tool" in m and ("list" in m or "available" in m or "all" in m):
        return "Available tools: NETWORK — Port Scanner, Quick Top 100, Vuln Scan, UDP Scan, Firewall Detect, SMB Enum, SNMP Check, Banner Grab, ARP Scan. WEB — SQL Injection, XSS Scanner, Nikto, Header Audit, SSL/TLS Check, WAF Detect, CORS Check, Directory Enum, CMS Detect, Admin Finder. INFRA — SSH Audit, FTP Check, RDP Check, DB Exposure, Docker Check, K8s Check. RECON — WHOIS, DNS Lookup, Subdomain Enum, Traceroute, Local Network, My IP, System Info."

    if "how to" in m and ("scan" in m or "use" in m or "start" in m):
        return "How to use HARSHA: 1) Enter your target IP or domain in the TARGET field at the top. 2) Choose a tool from the sidebar (Network, Web, Infrastructure, or Recon). 3) Results appear in the Terminal tab. 4) Port scans populate the Ports tab. 5) Vulnerability findings go to the Threats tab. 6) Check Risk Analysis and Threat Graph tabs for visual insights. 7) Click 'Download Report' for a full VAPT report."

    # --- Explicit search triggers ---
    search_prefixes = ["search ", "google ", "look up ", "find "]
    for prefix in search_prefixes:
        if m.startswith(prefix):
            search_query = msg[len(prefix):].strip()
            if search_query:
                result = ai_search_answer(search_query)
                if result:
                    return result
            break

    # --- "Who is" / "What is" / general questions → always try search ---
    question_starters = ["who is", "who are", "what is", "what are", "where is",
                         "when was", "when did", "how does", "how do", "how many",
                         "tell me about", "define ", "meaning of", "ceo of",
                         "founder of", "president of", "capital of"]
    for starter in question_starters:
        if m.startswith(starter) or starter in m:
            result = ai_search_answer(msg)
            if result:
                return result
            break

    # --- Catch-all: Search the web ---
    search_result = ai_search_answer(msg)
    if search_result:
        return search_result

    # Final fallback with helpful message
    if not HAS_REQUESTS:
        return "⚠️ Web search unavailable — 'requests' library not installed. Run: pip install requests. For now, I can answer VAPT and cybersecurity questions from my built-in knowledge. Try: 'What is SQL injection?', 'Explain OWASP Top 10', 'How to secure SSH?'"

    return "🔍 I searched but couldn't find a clear answer for: \"" + msg + "\". This might be because: the topic is very niche, or there's a network issue. Try rephrasing, or ask about: security concepts, OWASP, CVEs, network attacks, encryption, tool usage. You can also prefix with 'search' like: 'search Fluentgrid CEO'"

@app.route("/voice")
def voice():
    if os.path.exists(VOICE_FILE): return send_file(VOICE_FILE, mimetype="audio/mpeg")
    return jsonify({"error":"No voice"}), 404

@app.route("/scan", methods=["POST"])
def scan():
    data = request.json
    tool = data.get("tool","")
    target = data.get("target","").strip()
    no_target = ["network_scan","my_ip","system_info","weather","arp_scan"]
    if tool not in no_target and not target:
        return jsonify({"error":True,"output":"Please enter a target IP or domain first.","timestamp":""}), 200

    handlers = {
        "nmap_quick":    (lambda: nmap_quick(target),    "nmap",    "Quick scan done on "+target),
        "nmap_full":     (lambda: nmap_full(target),     "nmap",    "Full scan done on "+target),
        "nmap_vuln":     (lambda: nmap_vuln(target),     "nmap",    "Vulnerability scan done on "+target),
        "nmap_os":       (lambda: nmap_os(target),       "nmap",    "OS detection done for "+target),
        "nmap_udp":      (lambda: nmap_udp(target),      "nmap",    "UDP scan done for "+target),
        "nmap_firewall": (lambda: nmap_firewall(target), "nmap",    "Firewall detection done for "+target),
        "nmap_banner":   (lambda: nmap_banner(target),   "nmap",    "Banner grab done for "+target),
        "arp_scan":      (nmap_arp,                      "nmap",    "ARP scan done Harsha"),
        "smb_enum":      (lambda: smb_enum(target),      "nmap",    "SMB enumeration done for "+target),
        "snmp_enum":     (lambda: snmp_enum(target),     "nmap",    "SNMP enumeration done for "+target),
        "dns_zone":      (lambda: dns_zone_transfer(target),"recon","DNS zone transfer done for "+target),
        "web_headers":   (lambda: web_headers(target),   "headers", "HTTP headers checked for "+target),
        "web_ssl":       (lambda: web_ssl(target),       "ssl",     "SSL analysis done for "+target),
        "web_waf":       (lambda: web_waf(target),       "web",     "WAF detection done for "+target),
        "web_nikto":     (lambda: web_nikto(target),     "web",     "Nikto scan done for "+target),
        "web_dirscan":   (lambda: web_dirscan(target),   "web",     "Directory scan done for "+target),
        "web_admin":     (lambda: web_admin_finder(target),"web",   "Admin panel scan done for "+target),
        "web_cms":       (lambda: web_cms(target),       "web",     "CMS detection done for "+target),
        "web_cors":      (lambda: web_cors(target),      "headers", "CORS check done for "+target),
        "web_sqli":      (lambda: web_sqli(target),      "web",     "SQL injection test done for "+target),
        "web_xss":       (lambda: web_xss(target),       "web",     "XSS scan done for "+target),
        "web_methods":   (lambda: web_methods(target),   "web",     "HTTP methods test done for "+target),
        "web_subdomain": (lambda: web_subdomain(target), "recon",   "Subdomain scan done for "+target),
        "infra_ssh":     (lambda: infra_ssh_audit(target),"nmap",   "SSH audit done for "+target),
        "infra_ftp":     (lambda: infra_ftp(target),     "nmap",    "FTP check done for "+target),
        "infra_rdp":     (lambda: infra_rdp(target),     "nmap",    "RDP check done for "+target),
        "infra_db":      (lambda: infra_db_check(target),"nmap",    "Database exposure check done for "+target),
        "infra_docker":  (lambda: infra_docker(target),  "nmap",    "Docker and Kubernetes check done for "+target),
        "infra_cve":     (lambda: infra_cve_scan(target),"nmap",    "CVE scan done for "+target),
        "infra_winrm":   (lambda: infra_winrm(target),   "nmap",    "WinRM check done for "+target),
        "infra_snmp":    (lambda: infra_snmp(target),    "nmap",    "SNMP audit done for "+target),
        "whois":         (lambda: do_whois(target),      "recon",   "WHOIS done for "+target),
        "dns":           (lambda: do_dns(target),        "recon",   "DNS records fetched for "+target),
        "ip_info":       (lambda: do_ip_info(target),    "recon",   "IP info retrieved for "+target),
        "ping":          (lambda: do_ping(target),       "recon",   "Ping done for "+target),
        "traceroute":    (lambda: do_trace(target),      "recon",   "Traceroute done to "+target),
        "network_scan":  (do_netscan,                    "nmap",    "Local network scan done Harsha"),
        "my_ip":         (get_my_ip,                     "recon",   "Here are your IP addresses Harsha"),
        "system_info":   (get_sysinfo,                   "system",  "System status ready Harsha"),
        "weather":       (get_weather,                   "system",  "Weather retrieved for Hyderabad Harsha"),
        "nuclei_full":   (lambda: nuclei_full(target),   "nuclei",  "Nuclei full scan done on "+target),
        "nuclei_cve":    (lambda: nuclei_cve(target),    "nuclei",  "Nuclei CVE scan done on "+target),
        "nuclei_misconfig":(lambda: nuclei_misconfig(target),"nuclei","Nuclei misconfiguration scan done on "+target),
        "nuclei_tech":   (lambda: nuclei_tech(target),   "nuclei",  "Nuclei tech detection done on "+target),
        "nuclei_critical":(lambda: nuclei_critical(target),"nuclei","Nuclei critical scan done on "+target),
        "nuclei_network":(lambda: nuclei_network(target),"nuclei",  "Nuclei network scan done on "+target),
    }
    # Alias mapping
    aliases = {
        "nmap_scan":"nmap_quick","nmap_top100":"nmap_full","udp_scan":"nmap_udp",
        "firewall_detect":"nmap_firewall","snmp_check":"snmp_enum","banner_grab":"nmap_banner",
        "sqlmap_check":"web_sqli","xss_scan":"web_xss","nikto_scan":"web_nikto",
        "header_check":"web_headers","ssl_check":"web_ssl","waf_detect":"web_waf",
        "cors_check":"web_cors","dir_enum":"web_dirscan","cms_detect":"web_cms",
        "admin_finder":"web_admin","ssh_audit":"infra_ssh","ftp_check":"infra_ftp",
        "rdp_check":"infra_rdp","db_expose":"infra_db","docker_check":"infra_docker",
        "k8s_check":"infra_docker","dns_lookup":"dns","subdomain_enum":"web_subdomain",
    }
    original_tool = tool
    tool = aliases.get(tool, tool)
    if tool not in handlers:
        return jsonify({"output":"Unknown tool: "+tool}), 200

    fn, tool_type, voice_text = handlers[tool]
    tool_display = TOOL_DISPLAY.get(tool, tool.upper())

    # --- Update status: INITIALIZING ---
    update_scan_status(
        active=True, tool=tool, tool_display=tool_display,
        target=target or "localhost", category=tool_type,
        phase="initializing", percent=5,
        start_time=time.time(), message="Initializing " + tool_display + "..."
    )

    # --- Start progress simulator in background ---
    est_duration = TOOL_DURATION.get(tool, 30)
    stop_progress = threading.Event()
    def progress_ticker():
        start = time.time()
        while not stop_progress.is_set():
            elapsed = time.time() - start
            # Simulate progress: fast start, slow near end (never reaches 95% until done)
            raw_pct = min(92, (elapsed / est_duration) * 85 + 5)
            # Add phase labels
            if elapsed < 2:
                phase, msg = "initializing", "Connecting to target..."
            elif elapsed < est_duration * 0.15:
                phase, msg = "scanning", "Probing target services..."
            elif elapsed < est_duration * 0.4:
                phase, msg = "scanning", "Scanning in progress..."
            elif elapsed < est_duration * 0.7:
                phase, msg = "scanning", "Deep analysis running..."
            elif elapsed < est_duration * 0.9:
                phase, msg = "analyzing", "Processing results..."
            else:
                phase, msg = "analyzing", "Finalizing scan..."
            update_scan_status(phase=phase, percent=int(raw_pct), message=msg)
            stop_progress.wait(0.8)

    ticker = threading.Thread(target=progress_ticker, daemon=True)
    ticker.start()

    # --- Execute the actual scan ---
    try:
        output = fn()
        stop_progress.set()
        ticker.join(timeout=2)

        # --- Analyze results ---
        update_scan_status(phase="analyzing", percent=95, message="Parsing results...")
        ports   = parse_open_ports(output) if tool_type == "nmap" else []
        threats = parse_vuln_threats(output, tool_type)
        if tool_type == "nuclei":
            nuclei_threats = parse_nuclei_threats(output)
            threats.extend(nuclei_threats)
        if ports:   voice_text += " Found "+str(len(ports))+" open ports."
        if threats: voice_text += " "+str(len(threats))+" threats detected!"
        speak_generate(voice_text)

        elapsed_total = round(time.time() - scan_status["start_time"], 1)

        # --- Update status: COMPLETE ---
        history_entry = {
            "tool": tool_display, "target": target or "localhost",
            "elapsed": elapsed_total, "ports": len(ports), "threats": len(threats),
            "time": datetime.datetime.now().strftime("%I:%M:%S %p")
        }
        with scan_lock:
            scan_status["history"].insert(0, history_entry)
            scan_status["history"] = scan_status["history"][:15]

        update_scan_status(
            active=False, phase="complete", percent=100,
            elapsed=elapsed_total,
            message="Complete — " + str(len(ports)) + " ports, " + str(len(threats)) + " threats in " + str(elapsed_total) + "s"
        )

        return jsonify({"output":output,"ports":ports,"threats":threats,"has_voice":True,
                        "timestamp":datetime.datetime.now().strftime("%I:%M:%S %p")})
    except Exception as e:
        stop_progress.set()
        update_scan_status(active=False, phase="error", percent=0, message="Error: " + str(e))
        return jsonify({"output":"Error: "+str(e),"ports":[],"threats":[],"has_voice":False,
                        "timestamp":datetime.datetime.now().strftime("%I:%M:%S %p")})

@app.route("/scan_status")
def get_scan_status():
    with scan_lock:
        return jsonify(scan_status)

@app.route("/chat", methods=["POST"])
def chat():
    msg = request.json.get("message","").strip()
    if not msg: return jsonify({"error":"empty"}), 400
    response = chat_response(msg)
    speak_generate(response)
    return jsonify({"response":response,"has_voice":True})

@app.route("/status")
def status():
    return jsonify({"status":"online","name":"HARSHA AI","version":"4.0"})


_HTML_B64 = (
"PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9IlVURi04"
"Ij4KPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlh"
"bC1zY2FsZT0xLjAiPgo8dGl0bGU+SEFSU0hBIOKAlCBWQVBUIENvbW1hbmQgU3VpdGU8L3RpdGxlPgo8"
"c2NyaXB0IHNyYz0iaHR0cHM6Ly9jZG5qcy5jbG91ZGZsYXJlLmNvbS9hamF4L2xpYnMvQ2hhcnQuanMv"
"NC40LjEvY2hhcnQudW1kLm1pbi5qcyI+PC9zY3JpcHQ+CjxsaW5rIGhyZWY9Imh0dHBzOi8vZm9udHMu"
"Z29vZ2xlYXBpcy5jb20vY3NzMj9mYW1pbHk9T3V0Zml0OndnaHRAMzAwOzQwMDs1MDA7NjAwOzcwMDs4"
"MDA7OTAwJmZhbWlseT1JQk0rUGxleCtNb25vOndnaHRAMzAwOzQwMDs1MDA7NjAwOzcwMCZmYW1pbHk9"
"U3luZTp3Z2h0QDQwMDs1MDA7NjAwOzcwMDs4MDAmZGlzcGxheT1zd2FwIiByZWw9InN0eWxlc2hlZXQi"
"Pgo8c3R5bGU+Ci8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT0KICAgSEFSU0hBIHY3LjAg4oCUIENyb3dkU3RyaWtlLUluc3BpcmVkIFZB"
"UFQgRGFzaGJvYXJkCiAgIFBhbGV0dGU6IE1hdHRlIEJsYWNrIMK3IFB1cmUgV2hpdGUgwrcgU2lnbmFs"
"IFJlZAogICA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09ICovCiosKjo6YmVmb3JlLCo6OmFmdGVye21hcmdpbjowO3BhZGRpbmc6MDtib3gt"
"c2l6aW5nOmJvcmRlci1ib3h9Cgo6cm9vdHsKICAvKiBCTEFDSyBTUEVDVFJVTSAqLwogIC0tYmxhY2s6"
"IzBhMGEwYzsKICAtLWJsYWNrLTI6IzExMTExNTsKICAtLWJsYWNrLTM6IzE4MTgxYzsKICAtLWJsYWNr"
"LTQ6IzFlMWUyNDsKICAtLWJsYWNrLTU6IzI4MjgyZjsKICAvKiBXSElURSBTUEVDVFJVTSAqLwogIC0t"
"d2hpdGU6I2ZmZmZmZjsKICAtLXdoaXRlLTI6I2Y3ZjdmODsKICAtLXdoaXRlLTM6I2VjZWNlZjsKICAt"
"LXdoaXRlLTQ6I2RkZGRlMjsKICAtLXdoaXRlLTU6I2M4YzhkMDsKICAvKiBSRUQg4oCUIFRIRSBJREVO"
"VElUWSAqLwogIC0tcmVkOiNlNjM5NDY7CiAgLS1yZWQtZGFyazojYzExMjFmOwogIC0tcmVkLWxpZ2h0"
"OiNmZjZiNmI7CiAgLS1yZWQtZ2xvdzpyZ2JhKDIzMCw1Nyw3MCwwLjM1KTsKICAtLXJlZC1kaW06cmdi"
"YSgyMzAsNTcsNzAsMC4wOCk7CiAgLS1yZWQtYm9yZGVyOnJnYmEoMjMwLDU3LDcwLDAuMik7CiAgLyog"
"U0VWRVJJVFkgKG9uIHdoaXRlKSAqLwogIC0tc2V2LWNyaXQ6I2Q5MDQyOTsKICAtLXNldi1jcml0LWJn"
"OnJnYmEoMjE3LDQsNDEsMC4wNik7CiAgLS1zZXYtY3JpdC1ib3JkZXI6cmdiYSgyMTcsNCw0MSwwLjE4"
"KTsKICAtLXNldi1oaWdoOiNlODVkMDQ7CiAgLS1zZXYtaGlnaC1iZzpyZ2JhKDIzMiw5Myw0LDAuMDYp"
"OwogIC0tc2V2LWhpZ2gtYm9yZGVyOnJnYmEoMjMyLDkzLDQsMC4xOCk7CiAgLS1zZXYtbWVkOiNlMDlm"
"M2U7CiAgLS1zZXYtbWVkLWJnOnJnYmEoMjI0LDE1OSw2MiwwLjA4KTsKICAtLXNldi1tZWQtYm9yZGVy"
"OnJnYmEoMjI0LDE1OSw2MiwwLjIpOwogIC0tc2V2LWxvdzojMmQ2YTRmOwogIC0tc2V2LWxvdy1iZzpy"
"Z2JhKDQ1LDEwNiw3OSwwLjA2KTsKICAtLXNldi1sb3ctYm9yZGVyOnJnYmEoNDUsMTA2LDc5LDAuMTgp"
"OwogIC8qIFRFWFQgKi8KICAtLXR4LWRhcms6IzBhMGEwYzsKICAtLXR4LWJvZHk6IzNhM2E0NDsKICAt"
"LXR4LW11dGVkOiM4YThhOTY7CiAgLS10eC1mYWludDojYjBiMGJhOwogIC0tdHgtb24tZGFyazojZjBm"
"MGYyOwogIC0tdHgtb24tZGFyay1tdXRlZDojOGE4YTk2OwogIC8qIExBWU9VVCAqLwogIC0tc2lkZWJh"
"ci13OjIzMHB4OwogIC0taGVhZGVyLWg6NjBweDsKICAtLXJhZGl1czo4cHg7CiAgLS1yYWRpdXMtbGc6"
"MTRweDsKICAtLXJhZGl1cy14bDoyMHB4Owp9CgpodG1sLGJvZHl7CiAgaGVpZ2h0OjEwMCU7b3ZlcmZs"
"b3c6aGlkZGVuOwogIGZvbnQtZmFtaWx5OidPdXRmaXQnLHN5c3RlbS11aSxzYW5zLXNlcmlmOwogIGJh"
"Y2tncm91bmQ6dmFyKC0td2hpdGUtMik7Y29sb3I6dmFyKC0tdHgtYm9keSk7CiAgZm9udC1zaXplOjEz"
"cHg7bGluZS1oZWlnaHQ6MS41OwogIC13ZWJraXQtZm9udC1zbW9vdGhpbmc6YW50aWFsaWFzZWQ7Cn0K"
"Ci8qIFNDUk9MTEJBUiDigJQgdGhpbiwgZGFyayAqLwo6Oi13ZWJraXQtc2Nyb2xsYmFye3dpZHRoOjVw"
"eDtoZWlnaHQ6NXB4fQo6Oi13ZWJraXQtc2Nyb2xsYmFyLXRyYWNre2JhY2tncm91bmQ6dHJhbnNwYXJl"
"bnR9Cjo6LXdlYmtpdC1zY3JvbGxiYXItdGh1bWJ7YmFja2dyb3VuZDp2YXIoLS13aGl0ZS00KTtib3Jk"
"ZXItcmFkaXVzOjEwcHh9Ci5zaWRlYmFyIDo6LXdlYmtpdC1zY3JvbGxiYXItdGh1bWJ7YmFja2dyb3Vu"
"ZDp2YXIoLS1ibGFjay01KX0KCi8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAgQU5JTUFUSU9OUwogICA9PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovCkBrZXlmcmFt"
"ZXMgZmFkZVVwe2Zyb217b3BhY2l0eTowO3RyYW5zZm9ybTp0cmFuc2xhdGVZKDE2cHgpfXRve29wYWNp"
"dHk6MTt0cmFuc2Zvcm06bm9uZX19CkBrZXlmcmFtZXMgZmFkZUlue2Zyb217b3BhY2l0eTowfXRve29w"
"YWNpdHk6MX19CkBrZXlmcmFtZXMgc2xpZGVJbkxlZnR7ZnJvbXtvcGFjaXR5OjA7dHJhbnNmb3JtOnRy"
"YW5zbGF0ZVgoLTIwcHgpfXRve29wYWNpdHk6MTt0cmFuc2Zvcm06bm9uZX19CkBrZXlmcmFtZXMgcHVs"
"c2V7MCUsMTAwJXtvcGFjaXR5OjF9NTAle29wYWNpdHk6LjR9fQpAa2V5ZnJhbWVzIHNjYW5saW5lezAl"
"e3RvcDotMnB4fTEwMCV7dG9wOjEwMCV9fQpAa2V5ZnJhbWVzIGdsb3d7MCUsMTAwJXtib3gtc2hhZG93"
"OjAgMCA4cHggdmFyKC0tcmVkLWdsb3cpfTUwJXtib3gtc2hhZG93OjAgMCAyMHB4IHZhcigtLXJlZC1n"
"bG93KSwwIDAgNDBweCByZ2JhKDIzMCw1Nyw3MCwwLjE1KX19CkBrZXlmcmFtZXMgc2hpbW1lcnswJXti"
"YWNrZ3JvdW5kLXBvc2l0aW9uOjIwMCUgMH0xMDAle2JhY2tncm91bmQtcG9zaXRpb246LTIwMCUgMH19"
"CkBrZXlmcmFtZXMgc3Bpbnt0b3t0cmFuc2Zvcm06cm90YXRlKDM2MGRlZyl9fQpAa2V5ZnJhbWVzIGJv"
"cmRlckdsb3d7MCUsMTAwJXtib3JkZXItY29sb3I6cmdiYSgyMzAsNTcsNzAsMC4xNSl9NTAle2JvcmRl"
"ci1jb2xvcjpyZ2JhKDIzMCw1Nyw3MCwwLjQpfX0KQGtleWZyYW1lcyB0eXBld3JpdGVye2Zyb217d2lk"
"dGg6MH10b3t3aWR0aDoxMDAlfX0KQGtleWZyYW1lcyBncmlkUHVsc2V7MCUsMTAwJXtvcGFjaXR5Oi4w"
"M301MCV7b3BhY2l0eTouMDZ9fQoKLyogPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PQogICBBUFAgTEFZT1VUCiAgID09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0gKi8KLmFwcHtk"
"aXNwbGF5OmZsZXg7aGVpZ2h0OjEwMHZoO3dpZHRoOjEwMHZ3fQoKLyogPT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQogICBTSURFQkFSIOKA"
"lCBNQVRURSBCTEFDSwogICA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09ICovCi5zaWRlYmFyewogIHdpZHRoOnZhcigtLXNpZGViYXItdyk7"
"bWluLXdpZHRoOnZhcigtLXNpZGViYXItdyk7CiAgYmFja2dyb3VuZDp2YXIoLS1ibGFjayk7CiAgZGlz"
"cGxheTpmbGV4O2ZsZXgtZGlyZWN0aW9uOmNvbHVtbjsKICBvdmVyZmxvdzpoaWRkZW47CiAgcG9zaXRp"
"b246cmVsYXRpdmU7CiAgei1pbmRleDoxMDsKfQovKiBTdWJ0bGUgZ3JpZCBwYXR0ZXJuIG9uIHNpZGVi"
"YXIgKi8KLnNpZGViYXI6OmJlZm9yZXsKICBjb250ZW50OicnO3Bvc2l0aW9uOmFic29sdXRlO2luc2V0"
"OjA7CiAgYmFja2dyb3VuZC1pbWFnZToKICAgIGxpbmVhci1ncmFkaWVudChyZ2JhKDIzMCw1Nyw3MCww"
"LjAzKSAxcHgsdHJhbnNwYXJlbnQgMXB4KSwKICAgIGxpbmVhci1ncmFkaWVudCg5MGRlZyxyZ2JhKDIz"
"MCw1Nyw3MCwwLjAzKSAxcHgsdHJhbnNwYXJlbnQgMXB4KTsKICBiYWNrZ3JvdW5kLXNpemU6MjRweCAy"
"NHB4OwogIGFuaW1hdGlvbjpncmlkUHVsc2UgNHMgZWFzZSBpbmZpbml0ZTsKICBwb2ludGVyLWV2ZW50"
"czpub25lOwp9Cgouc2lkZWJhci1zY3JvbGx7ZmxleDoxO292ZXJmbG93LXk6YXV0bztwb3NpdGlvbjpy"
"ZWxhdGl2ZTt6LWluZGV4OjF9CgovKiBMT0dPICovCi5zLWxvZ297CiAgcGFkZGluZzoxOHB4IDIwcHg7"
"ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6MTJweDsKICBib3JkZXItYm90dG9tOjFw"
"eCBzb2xpZCByZ2JhKDI1NSwyNTUsMjU1LDAuMDYpOwogIGFuaW1hdGlvbjpmYWRlSW4gLjZzIGVhc2U7"
"Cn0KLnMtbG9nby1tYXJrewogIHdpZHRoOjM2cHg7aGVpZ2h0OjM2cHg7Ym9yZGVyLXJhZGl1czp2YXIo"
"LS1yYWRpdXMpOwogIGJhY2tncm91bmQ6dmFyKC0tcmVkKTsKICBkaXNwbGF5OmZsZXg7YWxpZ24taXRl"
"bXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpjZW50ZXI7CiAgZm9udC1mYW1pbHk6J1N5bmUnLHNhbnMt"
"c2VyaWY7Zm9udC13ZWlnaHQ6ODAwO2ZvbnQtc2l6ZToxNnB4O2NvbG9yOiNmZmY7CiAgcG9zaXRpb246"
"cmVsYXRpdmU7CiAgYW5pbWF0aW9uOmdsb3cgM3MgZWFzZSBpbmZpbml0ZTsKfQoucy1sb2dvLXRleHR7"
"Zm9udC1mYW1pbHk6J1N5bmUnLHNhbnMtc2VyaWY7Zm9udC1zaXplOjE4cHg7Zm9udC13ZWlnaHQ6ODAw"
"O2NvbG9yOnZhcigtLXdoaXRlKTtsZXR0ZXItc3BhY2luZzoycHh9Ci5zLWxvZ28tc3Vie2ZvbnQtc2l6"
"ZTo5cHg7Y29sb3I6dmFyKC0tdHgtb24tZGFyay1tdXRlZCk7bGV0dGVyLXNwYWNpbmc6M3B4O2ZvbnQt"
"d2VpZ2h0OjUwMDttYXJnaW4tdG9wOjFweH0KCi8qIE5BViBTRUNUSU9OUyAqLwovKiBTSURFQkFSIFNF"
"QVJDSCAqLwoucy1zZWFyY2h7cGFkZGluZzoxMHB4IDEycHggNnB4O3Bvc2l0aW9uOnJlbGF0aXZlfQou"
"cy1zZWFyY2gtaW5wdXR7CiAgd2lkdGg6MTAwJTtiYWNrZ3JvdW5kOnZhcigtLWJsYWNrLTMpO2JvcmRl"
"cjoxcHggc29saWQgcmdiYSgyNTUsMjU1LDI1NSwwLjA2KTsKICBib3JkZXItcmFkaXVzOjZweDtwYWRk"
"aW5nOjhweCAxMnB4IDhweCAzMnB4O2NvbG9yOnZhcigtLXR4LW9uLWRhcmspOwogIGZvbnQtc2l6ZTox"
"MXB4O2ZvbnQtZmFtaWx5OidPdXRmaXQnLHNhbnMtc2VyaWY7b3V0bGluZTpub25lOwogIHRyYW5zaXRp"
"b246Ym9yZGVyLWNvbG9yIC4yczsKfQoucy1zZWFyY2gtaW5wdXQ6Zm9jdXN7Ym9yZGVyLWNvbG9yOnZh"
"cigtLXJlZCl9Ci5zLXNlYXJjaC1pbnB1dDo6cGxhY2Vob2xkZXJ7Y29sb3I6cmdiYSgyNTUsMjU1LDI1"
"NSwwLjIpfQoucy1zZWFyY2gtaWNvbntwb3NpdGlvbjphYnNvbHV0ZTtsZWZ0OjIycHg7dG9wOjUwJTt0"
"cmFuc2Zvcm06dHJhbnNsYXRlWSgtNTAlKTtmb250LXNpemU6MTJweDtvcGFjaXR5Oi4zO3BvaW50ZXIt"
"ZXZlbnRzOm5vbmV9CgovKiBEUk9QRE9XTiBTRUNUSU9OUyAqLwoucy1zZWN0aW9ue3BhZGRpbmc6NHB4"
"IDEycHggMnB4fQoucy1zZWN0aW9uLWhlYWRlcnsKICBkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2Vu"
"dGVyO2dhcDo4cHg7CiAgcGFkZGluZzo4cHggOHB4O2JvcmRlci1yYWRpdXM6NnB4O2N1cnNvcjpwb2lu"
"dGVyOwogIHRyYW5zaXRpb246YWxsIC4yczt1c2VyLXNlbGVjdDpub25lOwp9Ci5zLXNlY3Rpb24taGVh"
"ZGVyOmhvdmVye2JhY2tncm91bmQ6cmdiYSgyNTUsMjU1LDI1NSwwLjAzKX0KLnMtc2VjdGlvbi1pY29u"
"e2ZvbnQtc2l6ZToxNHB4O3dpZHRoOjIwcHg7dGV4dC1hbGlnbjpjZW50ZXI7ZmxleC1zaHJpbms6MDtv"
"cGFjaXR5Oi42fQoucy1zZWN0aW9uLXRpdGxlewogIGZvbnQtZmFtaWx5OidJQk0gUGxleCBNb25vJyxt"
"b25vc3BhY2U7CiAgZm9udC1zaXplOjlweDtmb250LXdlaWdodDo2MDA7Y29sb3I6dmFyKC0tdHgtb24t"
"ZGFyay1tdXRlZCk7CiAgbGV0dGVyLXNwYWNpbmc6Mi41cHg7dGV4dC10cmFuc2Zvcm06dXBwZXJjYXNl"
"O2ZsZXg6MTsKfQoucy1zZWN0aW9uLWNvdW50ewogIGZvbnQtZmFtaWx5OidJQk0gUGxleCBNb25vJyxt"
"b25vc3BhY2U7Zm9udC1zaXplOjhweDtmb250LXdlaWdodDo3MDA7CiAgcGFkZGluZzoycHggNnB4O2Jv"
"cmRlci1yYWRpdXM6OHB4OwogIGJhY2tncm91bmQ6cmdiYSgyNTUsMjU1LDI1NSwwLjA2KTtjb2xvcjp2"
"YXIoLS10eC1vbi1kYXJrLW11dGVkKTsKICBtaW4td2lkdGg6MThweDt0ZXh0LWFsaWduOmNlbnRlcjsK"
"fQoucy1zZWN0aW9uLWFycm93ewogIGZvbnQtc2l6ZToxMHB4O2NvbG9yOnJnYmEoMjU1LDI1NSwyNTUs"
"MC4yKTsKICB0cmFuc2l0aW9uOnRyYW5zZm9ybSAuM3MgY3ViaWMtYmV6aWVyKC40LDAsLjIsMSk7Cn0K"
"LnMtc2VjdGlvbi5vcGVuIC5zLXNlY3Rpb24tYXJyb3d7dHJhbnNmb3JtOnJvdGF0ZSgxODBkZWcpfQou"
"cy1zZWN0aW9uLWJvZHl7CiAgbWF4LWhlaWdodDowO292ZXJmbG93OmhpZGRlbjsKICB0cmFuc2l0aW9u"
"Om1heC1oZWlnaHQgLjM1cyBjdWJpYy1iZXppZXIoLjQsMCwuMiwxKSxvcGFjaXR5IC4zcztvcGFjaXR5"
"OjA7Cn0KLnMtc2VjdGlvbi5vcGVuIC5zLXNlY3Rpb24tYm9keXttYXgtaGVpZ2h0OjYwMHB4O29wYWNp"
"dHk6MX0KCi5zLW5hdnsKICBkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDoxMHB4Owog"
"IHBhZGRpbmc6N3B4IDEycHg7Ym9yZGVyLXJhZGl1czo2cHg7CiAgY3Vyc29yOnBvaW50ZXI7dHJhbnNp"
"dGlvbjphbGwgLjJzOwogIGNvbG9yOnJnYmEoMjU1LDI1NSwyNTUsMC40NSk7Zm9udC1zaXplOjEycHg7"
"Zm9udC13ZWlnaHQ6NTAwOwogIG1hcmdpbi1ib3R0b206MXB4O2JvcmRlcjoxcHggc29saWQgdHJhbnNw"
"YXJlbnQ7CiAgYmFja2dyb3VuZDp0cmFuc3BhcmVudDt3aWR0aDoxMDAlO3RleHQtYWxpZ246bGVmdDsK"
"ICBmb250LWZhbWlseTonT3V0Zml0JyxzYW5zLXNlcmlmOwogIHBvc2l0aW9uOnJlbGF0aXZlO292ZXJm"
"bG93OmhpZGRlbjsKfQoucy1uYXY6OmJlZm9yZXsKICBjb250ZW50OicnO3Bvc2l0aW9uOmFic29sdXRl"
"O2xlZnQ6MDt0b3A6MDtib3R0b206MDt3aWR0aDowOwogIGJhY2tncm91bmQ6dmFyKC0tcmVkKTt0cmFu"
"c2l0aW9uOndpZHRoIC4yNXM7Ym9yZGVyLXJhZGl1czo2cHggMCAwIDZweDsKfQoucy1uYXY6aG92ZXJ7"
"Y29sb3I6cmdiYSgyNTUsMjU1LDI1NSwwLjgpO2JhY2tncm91bmQ6cmdiYSgyNTUsMjU1LDI1NSwwLjA0"
"KX0KLnMtbmF2OmhvdmVyOjpiZWZvcmV7d2lkdGg6M3B4fQoucy1uYXYuYWN0aXZle2NvbG9yOiNmZmY7"
"YmFja2dyb3VuZDpyZ2JhKDIzMCw1Nyw3MCwwLjEyKTtib3JkZXItY29sb3I6cmdiYSgyMzAsNTcsNzAs"
"MC4xNSl9Ci5zLW5hdi5hY3RpdmU6OmJlZm9yZXt3aWR0aDozcHg7YmFja2dyb3VuZDp2YXIoLS1yZWQp"
"fQoucy1uYXYgLmljb3tmb250LXNpemU6MTRweDt3aWR0aDoyMHB4O3RleHQtYWxpZ246Y2VudGVyO2Zs"
"ZXgtc2hyaW5rOjB9Ci5zLW5hdiAubGJse2ZsZXg6MX0KLnMtdGFnewogIGZvbnQtZmFtaWx5OidJQk0g"
"UGxleCBNb25vJyxtb25vc3BhY2U7CiAgZm9udC1zaXplOjhweDtmb250LXdlaWdodDo3MDA7cGFkZGlu"
"ZzoycHggNnB4OwogIGJvcmRlci1yYWRpdXM6M3B4O2xldHRlci1zcGFjaW5nOi41cHg7Cn0KLnMtdGFn"
"LnJ7YmFja2dyb3VuZDpyZ2JhKDIzMCw1Nyw3MCwwLjIpO2NvbG9yOnZhcigtLXJlZC1saWdodCl9Ci5z"
"LXRhZy5ve2JhY2tncm91bmQ6cmdiYSgyMzIsOTMsNCwwLjE1KTtjb2xvcjojZmY4YzQyfQoKLyogU0lE"
"RUJBUiBGT09URVIgKi8KLnMtZm9vdGVyewogIHBhZGRpbmc6MTRweCAxNnB4O2JvcmRlci10b3A6MXB4"
"IHNvbGlkIHJnYmEoMjU1LDI1NSwyNTUsMC4wNik7CiAgZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNl"
"bnRlcjtnYXA6MTBweDsKICBwb3NpdGlvbjpyZWxhdGl2ZTt6LWluZGV4OjE7Cn0KLnMtYXZhdGFyewog"
"IHdpZHRoOjMycHg7aGVpZ2h0OjMycHg7Ym9yZGVyLXJhZGl1czo1MCU7CiAgYmFja2dyb3VuZDp2YXIo"
"LS1yZWQpOwogIGRpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OmNl"
"bnRlcjsKICBmb250LWZhbWlseTonU3luZScsc2Fucy1zZXJpZjtmb250LXNpemU6MTFweDtmb250LXdl"
"aWdodDo4MDA7Y29sb3I6I2ZmZjsKfQoucy11bmFtZXtmb250LXNpemU6MTJweDtmb250LXdlaWdodDo2"
"MDA7Y29sb3I6dmFyKC0td2hpdGUpfQoucy11cm9sZXtmb250LXNpemU6OS41cHg7Y29sb3I6dmFyKC0t"
"dHgtb24tZGFyay1tdXRlZCk7bGV0dGVyLXNwYWNpbmc6LjVweH0KCi8qID09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAgTUFJTiBBUkVB"
"CiAgID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT0gKi8KLm1haW57ZmxleDoxO2Rpc3BsYXk6ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47"
"b3ZlcmZsb3c6aGlkZGVuO21pbi13aWR0aDowO2JhY2tncm91bmQ6dmFyKC0td2hpdGUtMil9CgovKiA9"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09CiAgIEhFQURFUiDigJQgQkxBQ0sgQkFSCiAgID09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0gKi8KLmhlYWRlcnsKICBoZWlnaHQ6dmFy"
"KC0taGVhZGVyLWgpO21pbi1oZWlnaHQ6dmFyKC0taGVhZGVyLWgpOwogIHBhZGRpbmc6MCAyOHB4O2Rp"
"c3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjE2cHg7CiAgYmFja2dyb3VuZDp2YXIoLS1i"
"bGFjay0yKTsKICBwb3NpdGlvbjpyZWxhdGl2ZTt6LWluZGV4OjU7CiAgYW5pbWF0aW9uOmZhZGVJbiAu"
"NXMgZWFzZTsKfQovKiBSZWQgYWNjZW50IGxpbmUgdW5kZXIgaGVhZGVyICovCi5oZWFkZXI6OmFmdGVy"
"ewogIGNvbnRlbnQ6Jyc7cG9zaXRpb246YWJzb2x1dGU7Ym90dG9tOjA7bGVmdDowO3JpZ2h0OjA7aGVp"
"Z2h0OjJweDsKICBiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCg5MGRlZyx2YXIoLS1yZWQpLHZhcigt"
"LXJlZC1kYXJrKSx0cmFuc3BhcmVudCA4MCUpOwogIG9wYWNpdHk6LjY7Cn0KCi5oLWxlZnR7ZGlzcGxh"
"eTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6MTRweDtmbGV4OjE7bWluLXdpZHRoOjB9Ci5oLXRp"
"dGxlewogIGZvbnQtZmFtaWx5OidTeW5lJyxzYW5zLXNlcmlmOwogIGZvbnQtc2l6ZToxNXB4O2ZvbnQt"
"d2VpZ2h0OjcwMDtjb2xvcjp2YXIoLS13aGl0ZSk7CiAgbGV0dGVyLXNwYWNpbmc6MXB4O3doaXRlLXNw"
"YWNlOm5vd3JhcDsKfQouaC1zZXB7d2lkdGg6MXB4O2hlaWdodDoyOHB4O2JhY2tncm91bmQ6cmdiYSgy"
"NTUsMjU1LDI1NSwwLjEpO2ZsZXgtc2hyaW5rOjB9CgouaC10YXJnZXR7CiAgZGlzcGxheTpmbGV4O2Fs"
"aWduLWl0ZW1zOmNlbnRlcjtmbGV4OjE7bWF4LXdpZHRoOjQ0MHB4OwogIGJhY2tncm91bmQ6dmFyKC0t"
"YmxhY2stMyk7Ym9yZGVyOjFweCBzb2xpZCByZ2JhKDI1NSwyNTUsMjU1LDAuMDgpOwogIGJvcmRlci1y"
"YWRpdXM6dmFyKC0tcmFkaXVzKTtvdmVyZmxvdzpoaWRkZW47dHJhbnNpdGlvbjphbGwgLjNzOwp9Ci5o"
"LXRhcmdldDpmb2N1cy13aXRoaW57Ym9yZGVyLWNvbG9yOnZhcigtLXJlZCk7Ym94LXNoYWRvdzowIDAg"
"MCAzcHggdmFyKC0tcmVkLWdsb3cpfQouaC10YXJnZXQtcHJlewogIHBhZGRpbmc6MCAxMnB4O2ZvbnQt"
"ZmFtaWx5OidJQk0gUGxleCBNb25vJyxtb25vc3BhY2U7CiAgZm9udC1zaXplOjlweDtjb2xvcjp2YXIo"
"LS1yZWQpO2xldHRlci1zcGFjaW5nOjJweDsKICBib3JkZXItcmlnaHQ6MXB4IHNvbGlkIHJnYmEoMjU1"
"LDI1NSwyNTUsMC4wNik7Zm9udC13ZWlnaHQ6NjAwOwp9Ci5oLXRhcmdldC1pbnB1dHsKICBmbGV4OjE7"
"YmFja2dyb3VuZDpub25lO2JvcmRlcjpub25lO291dGxpbmU6bm9uZTsKICBjb2xvcjp2YXIoLS10eC1v"
"bi1kYXJrKTtmb250LXNpemU6MTNweDtwYWRkaW5nOjEwcHggMTRweDsKICBmb250LWZhbWlseTonT3V0"
"Zml0JyxzYW5zLXNlcmlmOwp9Ci5oLXRhcmdldC1pbnB1dDo6cGxhY2Vob2xkZXJ7Y29sb3I6cmdiYSgy"
"NTUsMjU1LDI1NSwwLjIpfQoKLmgtcmlnaHR7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtn"
"YXA6MTBweDtmbGV4LXNocmluazowfQouaC1zdGF0dXN7CiAgZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1z"
"OmNlbnRlcjtnYXA6NnB4OwogIHBhZGRpbmc6NXB4IDEycHg7Ym9yZGVyLXJhZGl1czoyMHB4OwogIGZv"
"bnQtc2l6ZToxMHB4O2ZvbnQtd2VpZ2h0OjYwMDtsZXR0ZXItc3BhY2luZzouOHB4OwogIGZvbnQtZmFt"
"aWx5OidJQk0gUGxleCBNb25vJyxtb25vc3BhY2U7CiAgYmFja2dyb3VuZDpyZ2JhKDQ1LDEwNiw3OSww"
"LjE1KTtjb2xvcjojNGFkZTgwOwp9Ci5oLXN0YXR1cyAuZG90e3dpZHRoOjZweDtoZWlnaHQ6NnB4O2Jv"
"cmRlci1yYWRpdXM6NTAlO2JhY2tncm91bmQ6Y3VycmVudENvbG9yO2FuaW1hdGlvbjpwdWxzZSAycyBp"
"bmZpbml0ZX0KLmgtY2xvY2t7Zm9udC1mYW1pbHk6J0lCTSBQbGV4IE1vbm8nLG1vbm9zcGFjZTtmb250"
"LXNpemU6MTFweDtjb2xvcjp2YXIoLS10eC1vbi1kYXJrLW11dGVkKX0KCi5idG4tcmVwb3J0ewogIGRp"
"c3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjdweDsKICBwYWRkaW5nOjhweCAyMHB4O2Jv"
"cmRlci1yYWRpdXM6dmFyKC0tcmFkaXVzKTsKICBiYWNrZ3JvdW5kOnZhcigtLXJlZCk7Y29sb3I6I2Zm"
"ZjsKICBib3JkZXI6bm9uZTtjdXJzb3I6cG9pbnRlcjtmb250LXNpemU6MTJweDtmb250LXdlaWdodDo2"
"MDA7CiAgZm9udC1mYW1pbHk6J091dGZpdCcsc2Fucy1zZXJpZjtsZXR0ZXItc3BhY2luZzouNXB4Owog"
"IHRyYW5zaXRpb246YWxsIC4yNXM7cG9zaXRpb246cmVsYXRpdmU7b3ZlcmZsb3c6aGlkZGVuOwp9Ci5i"
"dG4tcmVwb3J0OjpiZWZvcmV7CiAgY29udGVudDonJztwb3NpdGlvbjphYnNvbHV0ZTtpbnNldDowOwog"
"IGJhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDkwZGVnLHRyYW5zcGFyZW50LHJnYmEoMjU1LDI1NSwy"
"NTUsMC4xKSx0cmFuc3BhcmVudCk7CiAgdHJhbnNmb3JtOnRyYW5zbGF0ZVgoLTEwMCUpO3RyYW5zaXRp"
"b246dHJhbnNmb3JtIC42czsKfQouYnRuLXJlcG9ydDpob3ZlcntiYWNrZ3JvdW5kOnZhcigtLXJlZC1k"
"YXJrKTt0cmFuc2Zvcm06dHJhbnNsYXRlWSgtMXB4KTtib3gtc2hhZG93OjAgNHB4IDIwcHggdmFyKC0t"
"cmVkLWdsb3cpfQouYnRuLXJlcG9ydDpob3Zlcjo6YmVmb3Jle3RyYW5zZm9ybTp0cmFuc2xhdGVYKDEw"
"MCUpfQoKLyogPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PQogICBUQUIgTkFWIOKAlCBPTiBXSElURQogICA9PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovCi50YWItbmF2ewog"
"IGRpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjJweDsKICBwYWRkaW5nOjAgMjhweDti"
"YWNrZ3JvdW5kOnZhcigtLXdoaXRlKTsKICBib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS13aGl0"
"ZS0zKTsKICBhbmltYXRpb246ZmFkZUluIC42cyBlYXNlOwp9Ci50YWItYnRuewogIHBhZGRpbmc6MTRw"
"eCAyMnB4O2ZvbnQtc2l6ZToxMi41cHg7Zm9udC13ZWlnaHQ6NTAwOwogIGNvbG9yOnZhcigtLXR4LW11"
"dGVkKTtiYWNrZ3JvdW5kOm5vbmU7Ym9yZGVyOm5vbmU7Y3Vyc29yOnBvaW50ZXI7CiAgYm9yZGVyLWJv"
"dHRvbToycHggc29saWQgdHJhbnNwYXJlbnQ7CiAgdHJhbnNpdGlvbjphbGwgLjJzO2ZvbnQtZmFtaWx5"
"OidPdXRmaXQnLHNhbnMtc2VyaWY7CiAgZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6"
"OHB4OwogIHBvc2l0aW9uOnJlbGF0aXZlO2xldHRlci1zcGFjaW5nOi4zcHg7Cn0KLnRhYi1idG46aG92"
"ZXJ7Y29sb3I6dmFyKC0tdHgtZGFyayl9Ci50YWItYnRuLmFjdGl2ZXtjb2xvcjp2YXIoLS1yZWQpO2Jv"
"cmRlci1ib3R0b20tY29sb3I6dmFyKC0tcmVkKTtmb250LXdlaWdodDo3MDB9Ci50YWItYmFkZ2V7CiAg"
"Zm9udC1mYW1pbHk6J0lCTSBQbGV4IE1vbm8nLG1vbm9zcGFjZTsKICBmb250LXNpemU6OXB4O2ZvbnQt"
"d2VpZ2h0OjcwMDtwYWRkaW5nOjJweCA3cHg7CiAgYm9yZGVyLXJhZGl1czoxMHB4O2JhY2tncm91bmQ6"
"dmFyKC0td2hpdGUtMyk7CiAgY29sb3I6dmFyKC0tdHgtbXV0ZWQpO2Rpc3BsYXk6bm9uZTsKfQoudGFi"
"LWJhZGdlLnNob3d7ZGlzcGxheTppbmxpbmUtYmxvY2t9Ci50YWItYmFkZ2UuYi1yZWR7YmFja2dyb3Vu"
"ZDp2YXIoLS1zZXYtY3JpdC1iZyk7Y29sb3I6dmFyKC0tc2V2LWNyaXQpfQoudGFiLWJhZGdlLmItb3Jh"
"bmdle2JhY2tncm91bmQ6dmFyKC0tc2V2LWhpZ2gtYmcpO2NvbG9yOnZhcigtLXNldi1oaWdoKX0KCi8q"
"ID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT0KICAgQ09OVEVOVCDigJQgV0hJVEUgQVJFQQogICA9PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovCi5jb250ZW50e2ZsZXg6MTtv"
"dmVyZmxvdzpoaWRkZW47ZGlzcGxheTpmbGV4O2ZsZXgtZGlyZWN0aW9uOmNvbHVtbn0KLnRhYi1wYW5l"
"e2Rpc3BsYXk6bm9uZTtmbGV4OjE7b3ZlcmZsb3cteTphdXRvO3BhZGRpbmc6MjRweCAyOHB4fQoudGFi"
"LXBhbmUuYWN0aXZle2Rpc3BsYXk6YmxvY2s7YW5pbWF0aW9uOmZhZGVVcCAuNHMgZWFzZX0KCi8qID09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT0KICAgVEVSTUlOQUwg4oCUIEFMV0FZUyBEQVJLCiAgID09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0gKi8KLnRlcm1pbmFsLWNhcmR7CiAg"
"YmFja2dyb3VuZDp2YXIoLS1ibGFjayk7Ym9yZGVyOjFweCBzb2xpZCByZ2JhKDI1NSwyNTUsMjU1LDAu"
"MDYpOwogIGJvcmRlci1yYWRpdXM6dmFyKC0tcmFkaXVzLWxnKTtvdmVyZmxvdzpoaWRkZW47CiAgcG9z"
"aXRpb246cmVsYXRpdmU7CiAgYW5pbWF0aW9uOmZhZGVVcCAuNXMgZWFzZTsKfQovKiBTY2FuIGxpbmUg"
"ZWZmZWN0ICovCi50ZXJtaW5hbC1jYXJkOjphZnRlcnsKICBjb250ZW50OicnO3Bvc2l0aW9uOmFic29s"
"dXRlO2xlZnQ6MDtyaWdodDowO2hlaWdodDoycHg7CiAgYmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQo"
"OTBkZWcsdHJhbnNwYXJlbnQsdmFyKC0tcmVkLWdsb3cpLHRyYW5zcGFyZW50KTsKICBhbmltYXRpb246"
"c2NhbmxpbmUgNHMgbGluZWFyIGluZmluaXRlOwogIHBvaW50ZXItZXZlbnRzOm5vbmU7b3BhY2l0eTou"
"NTsKfQoudGVybS1oZWFkZXJ7CiAgZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5"
"LWNvbnRlbnQ6c3BhY2UtYmV0d2VlbjsKICBwYWRkaW5nOjEwcHggMThweDtib3JkZXItYm90dG9tOjFw"
"eCBzb2xpZCByZ2JhKDI1NSwyNTUsMjU1LDAuMDYpOwogIGJhY2tncm91bmQ6cmdiYSgwLDAsMCwwLjMp"
"Owp9Ci50ZXJtLWRvdHN7ZGlzcGxheTpmbGV4O2dhcDo2cHh9Ci50ZXJtLWRvdHMgc3Bhbnt3aWR0aDox"
"MHB4O2hlaWdodDoxMHB4O2JvcmRlci1yYWRpdXM6NTAlfQoudGVybS1kb3RzIC5kMXtiYWNrZ3JvdW5k"
"OnZhcigtLXJlZCl9Ci50ZXJtLWRvdHMgLmQye2JhY2tncm91bmQ6I2UwOWYzZX0KLnRlcm0tZG90cyAu"
"ZDN7YmFja2dyb3VuZDojMmQ2YTRmfQoudGVybS10aXRsZXtmb250LWZhbWlseTonSUJNIFBsZXggTW9u"
"bycsbW9ub3NwYWNlO2ZvbnQtc2l6ZToxMHB4O2NvbG9yOnZhcigtLXR4LW9uLWRhcmstbXV0ZWQpO2xl"
"dHRlci1zcGFjaW5nOjEuNXB4fQoudGVybS1hY3Rpb25ze2Rpc3BsYXk6ZmxleDtnYXA6NnB4fQoudGVy"
"bS1hY3R7CiAgcGFkZGluZzo0cHggMTJweDtib3JkZXItcmFkaXVzOjRweDsKICBiYWNrZ3JvdW5kOnJn"
"YmEoMjU1LDI1NSwyNTUsMC4wNSk7Ym9yZGVyOjFweCBzb2xpZCByZ2JhKDI1NSwyNTUsMjU1LDAuMDgp"
"OwogIGNvbG9yOnZhcigtLXR4LW9uLWRhcmstbXV0ZWQpO2ZvbnQtc2l6ZTo5LjVweDtmb250LXdlaWdo"
"dDo2MDA7CiAgZm9udC1mYW1pbHk6J0lCTSBQbGV4IE1vbm8nLG1vbm9zcGFjZTtjdXJzb3I6cG9pbnRl"
"cjsKICB0cmFuc2l0aW9uOmFsbCAuMTVzO2xldHRlci1zcGFjaW5nOi41cHg7Cn0KLnRlcm0tYWN0Omhv"
"dmVye2JhY2tncm91bmQ6cmdiYSgyNTUsMjU1LDI1NSwwLjEpO2NvbG9yOnZhcigtLXdoaXRlKX0KCi5s"
"b2FkaW5nLWJhcntoZWlnaHQ6MnB4O2JhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDkwZGVnLHZhcigt"
"LXJlZCksI2ZmNmI2Yix2YXIoLS1yZWQpKTtiYWNrZ3JvdW5kLXNpemU6MjAwJSAxMDAlO2FuaW1hdGlv"
"bjpzaGltbWVyIDEuNXMgaW5maW5pdGU7ZGlzcGxheTpub25lfQoKI3Rlcm1pbmFsLW91dHB1dHsKICBw"
"YWRkaW5nOjE2cHggMThweDttaW4taGVpZ2h0OjI2MHB4O21heC1oZWlnaHQ6NTB2aDsKICBvdmVyZmxv"
"dy15OmF1dG87Zm9udC1mYW1pbHk6J0lCTSBQbGV4IE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6MTEu"
"NXB4OwogIGNvbG9yOnZhcigtLXR4LW9uLWRhcmstbXV0ZWQpOwp9Ci50bHtwYWRkaW5nOjJweCAwO2xp"
"bmUtaGVpZ2h0OjEuNjU7d29yZC1icmVhazpicmVhay1hbGx9Ci50bC5oZHJ7Y29sb3I6dmFyKC0tcmVk"
"KTtmb250LXdlaWdodDo2MDB9Ci50bC5wcm9tcHR7Y29sb3I6IzRhZGU4MH0KLnRsLnJlc3VsdHtjb2xv"
"cjp2YXIoLS10eC1vbi1kYXJrLW11dGVkKX0KLnRsLmVycm9ye2NvbG9yOnZhcigtLXJlZC1saWdodCl9"
"Ci50bC5pbmZve2NvbG9yOnJnYmEoMjU1LDI1NSwyNTUsMC4zKX0KLmJsaW5re2FuaW1hdGlvbjpwdWxz"
"ZSAxcyBzdGVwLWVuZCBpbmZpbml0ZX0KCi8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAgREFTSEJPQVJEIENBUkRTIOKAlCBXSElU"
"RSBDQVJEUyBPTiBMSUdIVCBCRwogICA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovCi5kYXNoLWdyaWR7ZGlzcGxheTpncmlkO2dhcDox"
"OHB4fQouZGFzaC1ncmlkLmNvbHMtNHtncmlkLXRlbXBsYXRlLWNvbHVtbnM6cmVwZWF0KDQsMWZyKX0K"
"LmRhc2gtZ3JpZC5jb2xzLTN7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOnJlcGVhdCgzLDFmcil9Ci5kYXNo"
"LWdyaWQuY29scy0ye2dyaWQtdGVtcGxhdGUtY29sdW1uczpyZXBlYXQoMiwxZnIpfQouZGFzaC1ncmlk"
"LmNvbHMtMXtncmlkLXRlbXBsYXRlLWNvbHVtbnM6MWZyfQoKLmNhcmR7CiAgYmFja2dyb3VuZDp2YXIo"
"LS13aGl0ZSk7CiAgYm9yZGVyOjFweCBzb2xpZCB2YXIoLS13aGl0ZS0zKTsKICBib3JkZXItcmFkaXVz"
"OnZhcigtLXJhZGl1cy1sZyk7CiAgcGFkZGluZzoyMHB4IDIycHg7CiAgdHJhbnNpdGlvbjphbGwgLjI1"
"czsKICBwb3NpdGlvbjpyZWxhdGl2ZTsKICBhbmltYXRpb246ZmFkZVVwIC41cyBlYXNlIGJvdGg7Cn0K"
"LmNhcmQ6bnRoLWNoaWxkKDEpe2FuaW1hdGlvbi1kZWxheTouMDVzfQouY2FyZDpudGgtY2hpbGQoMil7"
"YW5pbWF0aW9uLWRlbGF5Oi4xc30KLmNhcmQ6bnRoLWNoaWxkKDMpe2FuaW1hdGlvbi1kZWxheTouMTVz"
"fQouY2FyZDpudGgtY2hpbGQoNCl7YW5pbWF0aW9uLWRlbGF5Oi4yc30KLmNhcmQ6aG92ZXJ7Ym9yZGVy"
"LWNvbG9yOnZhcigtLXdoaXRlLTQpO2JveC1zaGFkb3c6MCA0cHggMjBweCByZ2JhKDAsMCwwLDAuMDQp"
"fQoKLmNhcmQtaGVhZGVye2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250"
"ZW50OnNwYWNlLWJldHdlZW47bWFyZ2luLWJvdHRvbToxNnB4fQouY2FyZC10aXRsZXtmb250LXNpemU6"
"MTRweDtmb250LXdlaWdodDo3MDA7Y29sb3I6dmFyKC0tdHgtZGFyayk7Zm9udC1mYW1pbHk6J091dGZp"
"dCcsc2Fucy1zZXJpZn0KLmNhcmQtc3VidGl0bGV7Zm9udC1zaXplOjExcHg7Y29sb3I6dmFyKC0tdHgt"
"bXV0ZWQpO21hcmdpbi10b3A6MnB4fQoKLyogU1RBVCBOVU1CRVJTICovCi5zdGF0LW51bXsKICBmb250"
"LWZhbWlseTonU3luZScsc2Fucy1zZXJpZjsKICBmb250LXNpemU6MzRweDtmb250LXdlaWdodDo4MDA7"
"bGluZS1oZWlnaHQ6MTsKICBjb2xvcjp2YXIoLS10eC1kYXJrKTtsZXR0ZXItc3BhY2luZzotMXB4Owp9"
"Ci5zdGF0LW51bS5yZWR7Y29sb3I6dmFyKC0tc2V2LWNyaXQpfQouc3RhdC1udW0ub3Jhbmdle2NvbG9y"
"OnZhcigtLXNldi1oaWdoKX0KLnN0YXQtbnVtLnllbGxvd3tjb2xvcjp2YXIoLS1zZXYtbWVkKX0KLnN0"
"YXQtbnVtLmdyZWVue2NvbG9yOnZhcigtLXNldi1sb3cpfQouc3RhdC1udW0uYnJhbmR7Y29sb3I6dmFy"
"KC0tcmVkKX0KCi5zdGF0LWJhci13cmFwe21hcmdpbi10b3A6MTBweH0KLnN0YXQtYmFye2hlaWdodDo2"
"cHg7Ym9yZGVyLXJhZGl1czoxMHB4O2JhY2tncm91bmQ6dmFyKC0td2hpdGUtMyk7b3ZlcmZsb3c6aGlk"
"ZGVufQouc3RhdC1iYXItZmlsbHtoZWlnaHQ6MTAwJTtib3JkZXItcmFkaXVzOjEwcHg7dHJhbnNpdGlv"
"bjp3aWR0aCAuOHMgY3ViaWMtYmV6aWVyKC40LDAsLjIsMSl9Ci5zdGF0LWJhci1maWxsLnJlZHtiYWNr"
"Z3JvdW5kOmxpbmVhci1ncmFkaWVudCg5MGRlZyx2YXIoLS1zZXYtY3JpdCksI2Y4NzE3MSl9Ci5zdGF0"
"LWJhci1maWxsLm9yYW5nZXtiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCg5MGRlZyx2YXIoLS1zZXYt"
"aGlnaCksI2ZiOTIzYyl9Ci5zdGF0LWJhci1maWxsLnllbGxvd3tiYWNrZ3JvdW5kOmxpbmVhci1ncmFk"
"aWVudCg5MGRlZyx2YXIoLS1zZXYtbWVkKSwjZmJiZjI0KX0KLnN0YXQtYmFyLWZpbGwuZ3JlZW57YmFj"
"a2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoOTBkZWcsdmFyKC0tc2V2LWxvdyksIzM0ZDM5OSl9Ci5zdGF0"
"LWJhci1maWxsLmJyYW5ke2JhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDkwZGVnLHZhcigtLXJlZCks"
"dmFyKC0tcmVkLWxpZ2h0KSl9Cgouc3RhdC1zdWJ7Zm9udC1zaXplOjEwLjVweDtjb2xvcjp2YXIoLS10"
"eC1tdXRlZCk7bWFyZ2luLXRvcDo4cHg7Zm9udC1mYW1pbHk6J0lCTSBQbGV4IE1vbm8nLG1vbm9zcGFj"
"ZX0KCi8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT0KICAgUE9SVCBUQUJMRSDigJQgQ0xFQU4gV0hJVEUKICAgPT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PSAqLwoucG9ydC10"
"YWJsZS13cmFwe292ZXJmbG93LXg6YXV0b30KLnBvcnQtdGFibGV7d2lkdGg6MTAwJTtib3JkZXItY29s"
"bGFwc2U6Y29sbGFwc2U7Zm9udC1zaXplOjEycHh9Ci5wb3J0LXRhYmxlIHRoZWFkIHRoewogIHRleHQt"
"YWxpZ246bGVmdDtwYWRkaW5nOjEwcHggMTRweDsKICBmb250LWZhbWlseTonSUJNIFBsZXggTW9ubycs"
"bW9ub3NwYWNlOwogIGZvbnQtc2l6ZTo5cHg7Zm9udC13ZWlnaHQ6NzAwO2NvbG9yOnZhcigtLXR4LWZh"
"aW50KTsKICBsZXR0ZXItc3BhY2luZzoxLjVweDt0ZXh0LXRyYW5zZm9ybTp1cHBlcmNhc2U7CiAgYm9y"
"ZGVyLWJvdHRvbToycHggc29saWQgdmFyKC0td2hpdGUtMyk7CiAgYmFja2dyb3VuZDp2YXIoLS13aGl0"
"ZS0yKTsKfQoucG9ydC10YWJsZSB0Ym9keSB0cntib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS13"
"aGl0ZS0zKTt0cmFuc2l0aW9uOmJhY2tncm91bmQgLjE1c30KLnBvcnQtdGFibGUgdGJvZHkgdHI6aG92"
"ZXJ7YmFja2dyb3VuZDp2YXIoLS1yZWQtZGltKX0KLnBvcnQtdGFibGUgdGJvZHkgdHI6bGFzdC1jaGls"
"ZHtib3JkZXItYm90dG9tOm5vbmV9Ci5wb3J0LXRhYmxlIHRke3BhZGRpbmc6MTBweCAxNHB4O3ZlcnRp"
"Y2FsLWFsaWduOnRvcH0KLnAtbnVte2ZvbnQtZmFtaWx5OidJQk0gUGxleCBNb25vJyxtb25vc3BhY2U7"
"Zm9udC13ZWlnaHQ6NzAwO2NvbG9yOnZhcigtLXJlZCk7Zm9udC1zaXplOjEzcHh9Ci5wLXByb3Rve2Zv"
"bnQtZmFtaWx5OidJQk0gUGxleCBNb25vJyxtb25vc3BhY2U7Zm9udC1zaXplOjlweDtjb2xvcjp2YXIo"
"LS10eC1mYWludCl9Ci5wLXN2Y3tjb2xvcjp2YXIoLS10eC1kYXJrKTtmb250LXdlaWdodDo2MDA7Zm9u"
"dC1zaXplOjEycHh9Ci5wLXZlcntmb250LXNpemU6MTBweDtjb2xvcjp2YXIoLS10eC1tdXRlZCk7bWFy"
"Z2luLXRvcDoycHh9Ci5wLWRlc2N7Y29sb3I6dmFyKC0tdHgtbXV0ZWQpO2ZvbnQtc2l6ZToxMXB4O21h"
"eC13aWR0aDoyNjBweH0KLnAtZml4e2NvbG9yOnZhcigtLXNldi1sb3cpO2ZvbnQtc2l6ZToxMXB4O21h"
"eC13aWR0aDoyMjBweH0KCi8qIFNFVkVSSVRZIEJBREdFUyDigJQgb24gd2hpdGUgYmcgKi8KLnNldnsK"
"ICBkaXNwbGF5OmlubGluZS1mbGV4O3BhZGRpbmc6M3B4IDEwcHg7Ym9yZGVyLXJhZGl1czoyMHB4Owog"
"IGZvbnQtZmFtaWx5OidJQk0gUGxleCBNb25vJyxtb25vc3BhY2U7CiAgZm9udC1zaXplOjguNXB4O2Zv"
"bnQtd2VpZ2h0OjcwMDtsZXR0ZXItc3BhY2luZzouOHB4Owp9Ci5zZXYuQ1JJVElDQUx7YmFja2dyb3Vu"
"ZDp2YXIoLS1zZXYtY3JpdC1iZyk7Y29sb3I6dmFyKC0tc2V2LWNyaXQpO2JvcmRlcjoxcHggc29saWQg"
"dmFyKC0tc2V2LWNyaXQtYm9yZGVyKX0KLnNldi5ISUdIe2JhY2tncm91bmQ6dmFyKC0tc2V2LWhpZ2gt"
"YmcpO2NvbG9yOnZhcigtLXNldi1oaWdoKTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLXNldi1oaWdoLWJv"
"cmRlcil9Ci5zZXYuTUVESVVNe2JhY2tncm91bmQ6dmFyKC0tc2V2LW1lZC1iZyk7Y29sb3I6dmFyKC0t"
"c2V2LW1lZCk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1zZXYtbWVkLWJvcmRlcil9Ci5zZXYuTE9Xe2Jh"
"Y2tncm91bmQ6dmFyKC0tc2V2LWxvdy1iZyk7Y29sb3I6dmFyKC0tc2V2LWxvdyk7Ym9yZGVyOjFweCBz"
"b2xpZCB2YXIoLS1zZXYtbG93LWJvcmRlcil9CgovKiA9PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiAgIFRIUkVBVCBDQVJEUyDigJQgV0hJ"
"VEUgV0lUSCBSRUQgTEVGVCBCT1JERVIKICAgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PSAqLwoudGhyZWF0LWNhcmR7CiAgYmFja2dyb3Vu"
"ZDp2YXIoLS13aGl0ZSk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS13aGl0ZS0zKTsKICBib3JkZXItcmFk"
"aXVzOnZhcigtLXJhZGl1cy1sZyk7cGFkZGluZzoxOHB4IDIycHg7CiAgYm9yZGVyLWxlZnQ6NHB4IHNv"
"bGlkIHZhcigtLXdoaXRlLTQpOwogIHRyYW5zaXRpb246YWxsIC4yNXM7CiAgYW5pbWF0aW9uOmZhZGVV"
"cCAuNXMgZWFzZSBib3RoOwp9Ci50aHJlYXQtY2FyZDpob3Zlcntib3gtc2hhZG93OjAgNHB4IDIwcHgg"
"cmdiYSgwLDAsMCwwLjA1KTt0cmFuc2Zvcm06dHJhbnNsYXRlWSgtMXB4KX0KLnRocmVhdC1jYXJkLkNS"
"SVRJQ0FMe2JvcmRlci1sZWZ0LWNvbG9yOnZhcigtLXNldi1jcml0KX0KLnRocmVhdC1jYXJkLkhJR0h7"
"Ym9yZGVyLWxlZnQtY29sb3I6dmFyKC0tc2V2LWhpZ2gpfQoudGhyZWF0LWNhcmQuTUVESVVNe2JvcmRl"
"ci1sZWZ0LWNvbG9yOnZhcigtLXNldi1tZWQpfQoudGhyZWF0LWNhcmQuTE9Xe2JvcmRlci1sZWZ0LWNv"
"bG9yOnZhcigtLXNldi1sb3cpfQoudGMtaGRye2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7"
"anVzdGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW47bWFyZ2luLWJvdHRvbToxMHB4fQoudGMtbmFtZXtm"
"b250LXNpemU6MTNweDtmb250LXdlaWdodDo3MDA7Y29sb3I6dmFyKC0tdHgtZGFyayl9Ci50Yy1kZXNj"
"e2ZvbnQtc2l6ZToxMnB4O2NvbG9yOnZhcigtLXR4LW11dGVkKTttYXJnaW4tYm90dG9tOjE0cHg7bGlu"
"ZS1oZWlnaHQ6MS43fQoudGMtZml4ewogIHBhZGRpbmc6MTBweCAxNHB4O2JvcmRlci1yYWRpdXM6dmFy"
"KC0tcmFkaXVzKTsKICBiYWNrZ3JvdW5kOnZhcigtLXNldi1sb3ctYmcpO2JvcmRlcjoxcHggc29saWQg"
"dmFyKC0tc2V2LWxvdy1ib3JkZXIpOwp9Ci50Yy1maXgtbGFiZWx7Zm9udC1mYW1pbHk6J0lCTSBQbGV4"
"IE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6OC41cHg7Zm9udC13ZWlnaHQ6NzAwO2NvbG9yOnZhcigt"
"LXNldi1sb3cpO2xldHRlci1zcGFjaW5nOjEuNXB4O21hcmdpbi1ib3R0b206M3B4fQoudGMtZml4LXRl"
"eHR7Zm9udC1zaXplOjExcHg7Y29sb3I6dmFyKC0tc2V2LWxvdyk7bGluZS1oZWlnaHQ6MS41fQoKLyog"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PQogICBDSEFSVCBDQVJEUwogICA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovCi5jaGFydC13cmFwe3Bvc2l0aW9uOnJlbGF0aXZl"
"O21pbi1oZWlnaHQ6MjAwcHh9Ci5jaGFydC13cmFwIGNhbnZhc3t3aWR0aDoxMDAlIWltcG9ydGFudDto"
"ZWlnaHQ6MTAwJSFpbXBvcnRhbnR9CgovKiBSSVNLIEdBVUdFICovCi5yaXNrLWdhdWdle2Rpc3BsYXk6"
"ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjI4cHg7cGFkZGluZzo4cHggMH0KLnJpc2stY2lyY2xl"
"ewogIHdpZHRoOjExMHB4O2hlaWdodDoxMTBweDtib3JkZXItcmFkaXVzOjUwJTsKICBkaXNwbGF5OmZs"
"ZXg7ZmxleC1kaXJlY3Rpb246Y29sdW1uO2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6"
"Y2VudGVyOwogIGJvcmRlcjozcHggc29saWQgdmFyKC0td2hpdGUtMyk7cG9zaXRpb246cmVsYXRpdmU7"
"ZmxleC1zaHJpbms6MDsKfQoucmlzay1jaXJjbGU6OmFmdGVyewogIGNvbnRlbnQ6Jyc7cG9zaXRpb246"
"YWJzb2x1dGU7aW5zZXQ6LTNweDtib3JkZXItcmFkaXVzOjUwJTsKICBib3JkZXI6M3B4IHNvbGlkIHRy"
"YW5zcGFyZW50O2JvcmRlci10b3AtY29sb3I6Y3VycmVudENvbG9yOwogIGFuaW1hdGlvbjpzcGluIDIu"
"NXMgbGluZWFyIGluZmluaXRlOwp9Ci5yaXNrLXZhbHtmb250LWZhbWlseTonU3luZScsc2Fucy1zZXJp"
"Zjtmb250LXNpemU6MzZweDtmb250LXdlaWdodDo4MDA7bGluZS1oZWlnaHQ6MX0KLnJpc2stbGFiZWx7"
"Zm9udC1mYW1pbHk6J0lCTSBQbGV4IE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6OXB4O2ZvbnQtd2Vp"
"Z2h0OjcwMDtsZXR0ZXItc3BhY2luZzoycHg7bWFyZ2luLXRvcDo0cHg7Y29sb3I6dmFyKC0tdHgtbXV0"
"ZWQpfQoucmlzay1kZXRhaWxze2Rpc3BsYXk6ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47Z2FwOjEw"
"cHh9Ci5yaXNrLXJvd3tkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDoxMHB4O2ZvbnQt"
"c2l6ZToxMnB4O2NvbG9yOnZhcigtLXR4LWJvZHkpfQoucmlzay1kb3R7d2lkdGg6OHB4O2hlaWdodDo4"
"cHg7Ym9yZGVyLXJhZGl1czo1MCU7ZmxleC1zaHJpbms6MH0KLnJpc2stdmFsLXNte2ZvbnQtZmFtaWx5"
"OidJQk0gUGxleCBNb25vJyxtb25vc3BhY2U7Zm9udC13ZWlnaHQ6NzAwO21hcmdpbi1sZWZ0OmF1dG99"
"CgovKiA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09CiAgIEVNUFRZIFNUQVRFCiAgID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0gKi8KLmVtcHR5LXN0YXRle2Rpc3BsYXk6Zmxl"
"eDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpj"
"ZW50ZXI7cGFkZGluZzo2MHB4IDIwcHg7dGV4dC1hbGlnbjpjZW50ZXJ9Ci5lbXB0eS1pY297Zm9udC1z"
"aXplOjQwcHg7bWFyZ2luLWJvdHRvbToxNnB4O29wYWNpdHk6LjM1fQouZW1wdHktdGl0bGV7Zm9udC1z"
"aXplOjE0cHg7Zm9udC13ZWlnaHQ6NzAwO2NvbG9yOnZhcigtLXR4LW11dGVkKTttYXJnaW4tYm90dG9t"
"OjZweH0KLmVtcHR5LXN1Yntmb250LXNpemU6MTJweDtjb2xvcjp2YXIoLS10eC1mYWludCk7bWF4LXdp"
"ZHRoOjMwMHB4fQoKLyogPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PQogICBDSEFUIFBBTkVMIOKAlCBEQVJLIEJPVFRPTSBCQVIKICAgPT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PSAqLwouY2hhdC1wYW5lbHsKICBib3JkZXItdG9wOjJweCBzb2xpZCB2YXIoLS1yZWQpOwogIGJhY2tn"
"cm91bmQ6dmFyKC0tYmxhY2spOwogIGRpc3BsYXk6ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47CiAg"
"bWF4LWhlaWdodDoyNDBweDt0cmFuc2l0aW9uOm1heC1oZWlnaHQgLjM1cyBjdWJpYy1iZXppZXIoLjQs"
"MCwuMiwxKTsKICBwb3NpdGlvbjpyZWxhdGl2ZTsKfQouY2hhdC1wYW5lbC5jb2xsYXBzZWR7bWF4LWhl"
"aWdodDo0NnB4fQouY2hhdC10b2dnbGV7CiAgZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtq"
"dXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2VlbjsKICBwYWRkaW5nOjAgMjRweDtoZWlnaHQ6NDZweDtt"
"aW4taGVpZ2h0OjQ2cHg7CiAgY3Vyc29yOnBvaW50ZXI7Cn0KLmNoYXQtdG9nZ2xlLWxlZnR7ZGlzcGxh"
"eTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6MTBweH0KLmNoYXQtdG9nZ2xlLWxhYmVse2ZvbnQt"
"c2l6ZToxMnB4O2ZvbnQtd2VpZ2h0OjcwMDtjb2xvcjp2YXIoLS13aGl0ZSk7bGV0dGVyLXNwYWNpbmc6"
"LjVweH0KLmNoYXQtdG9nZ2xlLXN0YXR1c3tmb250LXNpemU6MTBweDtjb2xvcjojNGFkZTgwO2ZvbnQt"
"d2VpZ2h0OjUwMH0KLmNoYXQtYXJyb3d7Zm9udC1zaXplOjEycHg7Y29sb3I6dmFyKC0tdHgtb24tZGFy"
"ay1tdXRlZCk7dHJhbnNpdGlvbjp0cmFuc2Zvcm0gLjNzfQouY2hhdC1wYW5lbC5jb2xsYXBzZWQgLmNo"
"YXQtYXJyb3d7dHJhbnNmb3JtOnJvdGF0ZSgxODBkZWcpfQoKI2NoYXQtbWVzc2FnZXN7ZmxleDoxO292"
"ZXJmbG93LXk6YXV0bztwYWRkaW5nOjEwcHggMjRweH0KLm1zZ3tkaXNwbGF5OmZsZXg7Z2FwOjEwcHg7"
"bWFyZ2luLWJvdHRvbToxMHB4O2FuaW1hdGlvbjpmYWRlVXAgLjNzIGVhc2V9Ci5tc2ctYXZhdGFyewog"
"IHdpZHRoOjI2cHg7aGVpZ2h0OjI2cHg7Ym9yZGVyLXJhZGl1czo2cHg7CiAgZGlzcGxheTpmbGV4O2Fs"
"aWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyOwogIGZvbnQtc2l6ZTo4cHg7Zm9u"
"dC13ZWlnaHQ6NzAwO2ZsZXgtc2hyaW5rOjA7CiAgZm9udC1mYW1pbHk6J0lCTSBQbGV4IE1vbm8nLG1v"
"bm9zcGFjZTsKfQoubXNnLmFpIC5tc2ctYXZhdGFye2JhY2tncm91bmQ6cmdiYSgyMzAsNTcsNzAsMC4x"
"NSk7Y29sb3I6dmFyKC0tcmVkLWxpZ2h0KX0KLm1zZy51c2VyIC5tc2ctYXZhdGFye2JhY2tncm91bmQ6"
"cmdiYSgyNTUsMjU1LDI1NSwwLjA4KTtjb2xvcjp2YXIoLS10eC1vbi1kYXJrLW11dGVkKX0KLm1zZy1i"
"b2R5ewogIGJhY2tncm91bmQ6dmFyKC0tYmxhY2stMyk7Ym9yZGVyOjFweCBzb2xpZCByZ2JhKDI1NSwy"
"NTUsMjU1LDAuMDYpOwogIGJvcmRlci1yYWRpdXM6dmFyKC0tcmFkaXVzKTtwYWRkaW5nOjlweCAxM3B4"
"OwogIGZvbnQtc2l6ZToxMnB4O2xpbmUtaGVpZ2h0OjEuNjtjb2xvcjp2YXIoLS10eC1vbi1kYXJrLW11"
"dGVkKTttYXgtd2lkdGg6ODUlOwp9CgouY2hhdC1pbnB1dC1yb3d7ZGlzcGxheTpmbGV4O2dhcDo4cHg7"
"cGFkZGluZzo4cHggMjRweCAxMnB4fQouY2hhdC1pbnB1dHsKICBmbGV4OjE7YmFja2dyb3VuZDp2YXIo"
"LS1ibGFjay0zKTtib3JkZXI6MXB4IHNvbGlkIHJnYmEoMjU1LDI1NSwyNTUsMC4wOCk7CiAgYm9yZGVy"
"LXJhZGl1czp2YXIoLS1yYWRpdXMpO3BhZGRpbmc6OXB4IDE0cHg7CiAgY29sb3I6dmFyKC0tdHgtb24t"
"ZGFyayk7Zm9udC1zaXplOjEycHg7b3V0bGluZTpub25lOwogIGZvbnQtZmFtaWx5OidPdXRmaXQnLHNh"
"bnMtc2VyaWY7dHJhbnNpdGlvbjpib3JkZXItY29sb3IgLjJzOwp9Ci5jaGF0LWlucHV0OmZvY3Vze2Jv"
"cmRlci1jb2xvcjp2YXIoLS1yZWQpfQouY2hhdC1pbnB1dDo6cGxhY2Vob2xkZXJ7Y29sb3I6cmdiYSgy"
"NTUsMjU1LDI1NSwwLjIpfQouY2hhdC1zZW5kewogIHBhZGRpbmc6MCAyMHB4O2JvcmRlci1yYWRpdXM6"
"dmFyKC0tcmFkaXVzKTsKICBiYWNrZ3JvdW5kOnZhcigtLXJlZCk7Y29sb3I6I2ZmZjtib3JkZXI6bm9u"
"ZTsKICBmb250LXNpemU6MTJweDtmb250LXdlaWdodDo3MDA7Y3Vyc29yOnBvaW50ZXI7CiAgZm9udC1m"
"YW1pbHk6J091dGZpdCcsc2Fucy1zZXJpZjt0cmFuc2l0aW9uOmFsbCAuMnM7Cn0KLmNoYXQtc2VuZDpo"
"b3ZlcntiYWNrZ3JvdW5kOnZhcigtLXJlZC1kYXJrKX0KCi8qID09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAgUkVQT1JUIE1PREFMCiAg"
"ID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT0gKi8KLm1vZGFsLW92ZXJsYXl7ZGlzcGxheTpub25lO3Bvc2l0aW9uOmZpeGVkO2luc2V0OjA7"
"ei1pbmRleDoxMDAwO2JhY2tncm91bmQ6cmdiYSgwLDAsMCwwLjUpO2JhY2tkcm9wLWZpbHRlcjpibHVy"
"KDEycHgpO2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyfQoubW9kYWwtb3Zl"
"cmxheS5vcGVue2Rpc3BsYXk6ZmxleH0KLm1vZGFsLWJveHtiYWNrZ3JvdW5kOnZhcigtLXdoaXRlKTti"
"b3JkZXItcmFkaXVzOnZhcigtLXJhZGl1cy14bCk7d2lkdGg6OTAlO21heC13aWR0aDo5MDBweDttYXgt"
"aGVpZ2h0Ojg1dmg7ZGlzcGxheTpmbGV4O2ZsZXgtZGlyZWN0aW9uOmNvbHVtbjtib3gtc2hhZG93OjAg"
"MjRweCA2NHB4IHJnYmEoMCwwLDAsMC4zKTthbmltYXRpb246ZmFkZVVwIC40cyBlYXNlfQoubW9kYWwt"
"aGRye2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OnNwYWNlLWJl"
"dHdlZW47cGFkZGluZzoxOHB4IDI0cHg7Ym9yZGVyLWJvdHRvbToxcHggc29saWQgdmFyKC0td2hpdGUt"
"Myl9Ci5tb2RhbC10aXRsZXtmb250LWZhbWlseTonU3luZScsc2Fucy1zZXJpZjtmb250LXNpemU6MTZw"
"eDtmb250LXdlaWdodDo4MDA7Y29sb3I6dmFyKC0tdHgtZGFyayk7bGV0dGVyLXNwYWNpbmc6MXB4fQou"
"bW9kYWwtY2xvc2V7cGFkZGluZzo2cHggMTZweDtib3JkZXItcmFkaXVzOjZweDtiYWNrZ3JvdW5kOnZh"
"cigtLXdoaXRlLTIpO2JvcmRlcjoxcHggc29saWQgdmFyKC0td2hpdGUtMyk7Y29sb3I6dmFyKC0tdHgt"
"bXV0ZWQpO2N1cnNvcjpwb2ludGVyO2ZvbnQtc2l6ZToxMXB4O2ZvbnQtd2VpZ2h0OjYwMDtmb250LWZh"
"bWlseTonSUJNIFBsZXggTW9ubycsbW9ub3NwYWNlO3RyYW5zaXRpb246YWxsIC4xNXN9Ci5tb2RhbC1j"
"bG9zZTpob3ZlcntiYWNrZ3JvdW5kOnZhcigtLXdoaXRlLTMpfQoubW9kYWwtYm9keXtmbGV4OjE7b3Zl"
"cmZsb3cteTphdXRvO3BhZGRpbmc6MjRweH0KLm1vZGFsLWZvb3RlcntkaXNwbGF5OmZsZXg7Z2FwOjEw"
"cHg7cGFkZGluZzoxNnB4IDI0cHg7Ym9yZGVyLXRvcDoxcHggc29saWQgdmFyKC0td2hpdGUtMyl9Ci5k"
"bC1idG57cGFkZGluZzo4cHggMjBweDtib3JkZXItcmFkaXVzOnZhcigtLXJhZGl1cyk7Ym9yZGVyOm5v"
"bmU7Y3Vyc29yOnBvaW50ZXI7Zm9udC1zaXplOjEycHg7Zm9udC13ZWlnaHQ6NzAwO3RyYW5zaXRpb246"
"YWxsIC4ycztmb250LWZhbWlseTonT3V0Zml0JyxzYW5zLXNlcmlmfQouZGwtYnRuLnByaW1hcnl7YmFj"
"a2dyb3VuZDp2YXIoLS1yZWQpO2NvbG9yOiNmZmZ9Ci5kbC1idG4ucHJpbWFyeTpob3ZlcntiYWNrZ3Jv"
"dW5kOnZhcigtLXJlZC1kYXJrKX0KLmRsLWJ0bi5zZWNvbmRhcnl7YmFja2dyb3VuZDp2YXIoLS13aGl0"
"ZS0yKTtjb2xvcjp2YXIoLS10eC1ib2R5KTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLXdoaXRlLTMpfQou"
"ZGwtYnRuLnNlY29uZGFyeTpob3ZlcntiYWNrZ3JvdW5kOnZhcigtLXdoaXRlLTMpfQoKLyogUmVwb3J0"
"IGlubmVyICovCi5ycC1oZHJ7dGV4dC1hbGlnbjpjZW50ZXI7cGFkZGluZzoxNnB4IDAgMjBweDtib3Jk"
"ZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS13aGl0ZS0zKTttYXJnaW4tYm90dG9tOjIwcHh9Ci5ycC10"
"e2ZvbnQtZmFtaWx5OidTeW5lJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZToyMHB4O2ZvbnQtd2VpZ2h0Ojgw"
"MDtjb2xvcjp2YXIoLS1yZWQpO2xldHRlci1zcGFjaW5nOjJweH0KLnJwLXN7Zm9udC1zaXplOjExcHg7"
"Y29sb3I6dmFyKC0tdHgtbXV0ZWQpO21hcmdpbi10b3A6NHB4fQoucnAtc2Vje21hcmdpbi1ib3R0b206"
"MjBweH0KLnJwLXN0e2ZvbnQtZmFtaWx5OidJQk0gUGxleCBNb25vJyxtb25vc3BhY2U7Zm9udC1zaXpl"
"OjExcHg7Zm9udC13ZWlnaHQ6NzAwO2NvbG9yOnZhcigtLXJlZCk7bGV0dGVyLXNwYWNpbmc6MS41cHg7"
"bWFyZ2luLWJvdHRvbToxMHB4fQoucnAtcHJ7ZGlzcGxheTpncmlkO2dyaWQtdGVtcGxhdGUtY29sdW1u"
"czo4MHB4IDEyMHB4IDgwcHggMWZyO2dhcDo4cHg7cGFkZGluZzo2cHggMDtmb250LXNpemU6MTFweDti"
"b3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS13aGl0ZS0zKX0KLnJwLXRoe3BhZGRpbmc6MTBweCAx"
"NHB4O21hcmdpbi1ib3R0b206NnB4O2JvcmRlci1yYWRpdXM6dmFyKC0tcmFkaXVzKTtib3JkZXItbGVm"
"dDozcHggc29saWQgdmFyKC0td2hpdGUtNCk7YmFja2dyb3VuZDp2YXIoLS13aGl0ZS0yKX0KLnJwLXRo"
"LkNSSVRJQ0FMe2JvcmRlci1sZWZ0LWNvbG9yOnZhcigtLXNldi1jcml0KX0ucnAtdGguSElHSHtib3Jk"
"ZXItbGVmdC1jb2xvcjp2YXIoLS1zZXYtaGlnaCl9LnJwLXRoLk1FRElVTXtib3JkZXItbGVmdC1jb2xv"
"cjp2YXIoLS1zZXYtbWVkKX0ucnAtdGguTE9Xe2JvcmRlci1sZWZ0LWNvbG9yOnZhcigtLXNldi1sb3cp"
"fQoucnAtdG57Zm9udC13ZWlnaHQ6NzAwO2NvbG9yOnZhcigtLXR4LWRhcmspO2ZvbnQtc2l6ZToxMnB4"
"O21hcmdpbi1ib3R0b206NHB4fQoucnAtdGR7Zm9udC1zaXplOjExcHg7Y29sb3I6dmFyKC0tdHgtbXV0"
"ZWQpfQoucnAtdGZ7Zm9udC1zaXplOjExcHg7Y29sb3I6dmFyKC0tc2V2LWxvdyk7bWFyZ2luLXRvcDo0"
"cHh9CgovKiBOT1RJRklDQVRJT04gKi8KLm5vdGlmewogIHBvc2l0aW9uOmZpeGVkO3RvcDoyMHB4O3Jp"
"Z2h0OjIwcHg7ei1pbmRleDoyMDAwOwogIGJhY2tncm91bmQ6dmFyKC0tYmxhY2spO2JvcmRlcjoxcHgg"
"c29saWQgcmdiYSgyMzAsNTcsNzAsMC4yKTsKICBib3JkZXItcmFkaXVzOnZhcigtLXJhZGl1cyk7cGFk"
"ZGluZzoxMnB4IDIwcHg7CiAgY29sb3I6dmFyKC0td2hpdGUpO2ZvbnQtc2l6ZToxMnB4O2ZvbnQtd2Vp"
"Z2h0OjYwMDsKICBib3gtc2hhZG93OjAgOHB4IDMwcHggcmdiYSgwLDAsMCwwLjMpOwogIGFuaW1hdGlv"
"bjpmYWRlVXAgLjNzIGVhc2U7Cn0KCi8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAgU0NBTiBTVEFUVVMgVEFCIFNUWUxFUwogICA9"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09ICovCi5zY2FuLWluZGljYXRvcnsKICB3aWR0aDo0OHB4O2hlaWdodDo0OHB4O2JvcmRlci1yYWRp"
"dXM6NTAlOwogIGRpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OmNl"
"bnRlcjsKICBwb3NpdGlvbjpyZWxhdGl2ZTtmbGV4LXNocmluazowOwogIGJhY2tncm91bmQ6dmFyKC0t"
"d2hpdGUtMik7Ym9yZGVyOjJweCBzb2xpZCB2YXIoLS13aGl0ZS0zKTsKfQouc2Nhbi1pbmRpY2F0b3Iu"
"cnVubmluZ3tiYWNrZ3JvdW5kOnZhcigtLXJlZC1kaW0pO2JvcmRlci1jb2xvcjp2YXIoLS1yZWQtYm9y"
"ZGVyKX0KLnNjYW4taW5kaWNhdG9yLnJ1bm5pbmc6OmFmdGVyewogIGNvbnRlbnQ6Jyc7cG9zaXRpb246"
"YWJzb2x1dGU7aW5zZXQ6LTJweDtib3JkZXItcmFkaXVzOjUwJTsKICBib3JkZXI6MnB4IHNvbGlkIHRy"
"YW5zcGFyZW50O2JvcmRlci10b3AtY29sb3I6dmFyKC0tcmVkKTsKICBhbmltYXRpb246c3BpbiAxcyBs"
"aW5lYXIgaW5maW5pdGU7Cn0KLnNjYW4taW5kaWNhdG9yLmNvbXBsZXRle2JhY2tncm91bmQ6dmFyKC0t"
"c2V2LWxvdy1iZyk7Ym9yZGVyLWNvbG9yOnZhcigtLXNldi1sb3ctYm9yZGVyKX0KLnNjYW4taW5kaWNh"
"dG9yLmVycm9ye2JhY2tncm91bmQ6dmFyKC0tc2V2LWNyaXQtYmcpO2JvcmRlci1jb2xvcjp2YXIoLS1z"
"ZXYtY3JpdC1ib3JkZXIpfQouc2Nhbi1wY3R7Zm9udC1mYW1pbHk6J1N5bmUnLHNhbnMtc2VyaWY7Zm9u"
"dC1zaXplOjEzcHg7Zm9udC13ZWlnaHQ6ODAwO2NvbG9yOnZhcigtLXR4LW11dGVkKX0KLnNjYW4taW5k"
"aWNhdG9yLnJ1bm5pbmcgLnNjYW4tcGN0e2NvbG9yOnZhcigtLXJlZCl9Ci5zY2FuLWluZGljYXRvci5j"
"b21wbGV0ZSAuc2Nhbi1wY3R7Y29sb3I6dmFyKC0tc2V2LWxvdyl9Ci5zY2FuLWluZGljYXRvci5lcnJv"
"ciAuc2Nhbi1wY3R7Y29sb3I6dmFyKC0tc2V2LWNyaXQpfQouc2Nhbi1tZXRhLWl0ZW17CiAgZm9udC1m"
"YW1pbHk6J0lCTSBQbGV4IE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6MTBweDsKICBjb2xvcjp2YXIo"
"LS10eC1tdXRlZCk7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6NHB4Owp9Ci5zY2Fu"
"LW1ldGEtaXRlbSAuZG90e3dpZHRoOjVweDtoZWlnaHQ6NXB4O2JvcmRlci1yYWRpdXM6NTAlO2ZsZXgt"
"c2hyaW5rOjB9Ci5zY2FuLWJhci10cmFja3toZWlnaHQ6MTBweDtiYWNrZ3JvdW5kOnZhcigtLXdoaXRl"
"LTMpO2JvcmRlci1yYWRpdXM6MTBweDtvdmVyZmxvdzpoaWRkZW59Ci5zY2FuLWJhci1maWxsLWxpdmV7"
"CiAgaGVpZ2h0OjEwMCU7Ym9yZGVyLXJhZGl1czoxMHB4O3RyYW5zaXRpb246d2lkdGggLjZzIGN1Ymlj"
"LWJlemllciguNCwwLC4yLDEpOwogIGJhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDkwZGVnLHZhcigt"
"LXJlZCksdmFyKC0tcmVkLWxpZ2h0KSk7cG9zaXRpb246cmVsYXRpdmU7Cn0KLnNjYW4tYmFyLWZpbGwt"
"bGl2ZS5jb21wbGV0ZXtiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCg5MGRlZyx2YXIoLS1zZXYtbG93"
"KSwjMzRkMzk5KX0KLnNjYW4tYmFyLWZpbGwtbGl2ZTo6YWZ0ZXJ7CiAgY29udGVudDonJztwb3NpdGlv"
"bjphYnNvbHV0ZTtpbnNldDowOwogIGJhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDkwZGVnLHRyYW5z"
"cGFyZW50LHJnYmEoMjU1LDI1NSwyNTUsMC4yNSksdHJhbnNwYXJlbnQpOwogIGFuaW1hdGlvbjpzaGlt"
"bWVyIDEuNXMgaW5maW5pdGU7Cn0KLnRhYi1iYWRnZS5saXZle2Rpc3BsYXk6aW5saW5lLWJsb2NrO2Jh"
"Y2tncm91bmQ6dmFyKC0tcmVkKTtjb2xvcjojZmZmO2FuaW1hdGlvbjpwdWxzZSAxLjVzIGluZmluaXRl"
"fQoudGFiLWJhZGdlLmRvbmV7ZGlzcGxheTppbmxpbmUtYmxvY2s7YmFja2dyb3VuZDp2YXIoLS1zZXYt"
"bG93LWJnKTtjb2xvcjp2YXIoLS1zZXYtbG93KX0KCi8qIE1JTkkgU1RBVFMgSU4gSEVBREVSICovCi5o"
"LW1pbmktc3RhdHN7ZGlzcGxheTpmbGV4O2dhcDoxMHB4fQouaC1taW5pLXN0YXR7CiAgZm9udC1mYW1p"
"bHk6J0lCTSBQbGV4IE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6MTBweDsKICBjb2xvcjp2YXIoLS10"
"eC1vbi1kYXJrLW11dGVkKTtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDo0cHg7Cn0K"
"LmgtbWluaS1zdGF0IHN0cm9uZ3tjb2xvcjp2YXIoLS13aGl0ZSk7Zm9udC1zaXplOjExcHh9CgovKiBN"
"SU5JIFBST0dSRVNTIEJBUiAoYmVsb3cgaGVhZGVyKSAqLwouaC1taW5pLXByb2dyZXNzewogIGhlaWdo"
"dDozcHg7YmFja2dyb3VuZDp2YXIoLS1ibGFjay0zKTtwb3NpdGlvbjpyZWxhdGl2ZTtvdmVyZmxvdzpo"
"aWRkZW47CiAgb3BhY2l0eTowO3RyYW5zaXRpb246b3BhY2l0eSAuM3M7Cn0KLmgtbWluaS1wcm9ncmVz"
"cy5hY3RpdmV7b3BhY2l0eToxfQouaC1taW5pLWJhcnsKICBoZWlnaHQ6MTAwJTt3aWR0aDowJTsKICBi"
"YWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCg5MGRlZyx2YXIoLS1yZWQpLHZhcigtLXJlZC1saWdodCkp"
"OwogIHRyYW5zaXRpb246d2lkdGggLjVzIGN1YmljLWJlemllciguNCwwLC4yLDEpO3Bvc2l0aW9uOnJl"
"bGF0aXZlOwp9Ci5oLW1pbmktYmFyOjphZnRlcnsKICBjb250ZW50OicnO3Bvc2l0aW9uOmFic29sdXRl"
"O2luc2V0OjA7CiAgYmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoOTBkZWcsdHJhbnNwYXJlbnQscmdi"
"YSgyNTUsMjU1LDI1NSwwLjMpLHRyYW5zcGFyZW50KTsKICBhbmltYXRpb246c2hpbW1lciAxLjJzIGlu"
"ZmluaXRlOwp9CgovKiBUQVJHRVQgSElTVE9SWSBEUk9QRE9XTiAqLwouaC10YXJnZXQtaGlzdG9yeXsK"
"ICBkaXNwbGF5Om5vbmU7cG9zaXRpb246YWJzb2x1dGU7dG9wOjEwMCU7bGVmdDowO3JpZ2h0OjA7ei1p"
"bmRleDoxMDA7CiAgYmFja2dyb3VuZDp2YXIoLS1ibGFjay0yKTtib3JkZXI6MXB4IHNvbGlkIHJnYmEo"
"MjU1LDI1NSwyNTUsMC4xKTsKICBib3JkZXItcmFkaXVzOjAgMCB2YXIoLS1yYWRpdXMpIHZhcigtLXJh"
"ZGl1cyk7CiAgYm94LXNoYWRvdzowIDhweCAyNHB4IHJnYmEoMCwwLDAsMC40KTttYXgtaGVpZ2h0OjIw"
"MHB4O292ZXJmbG93LXk6YXV0bzsKfQouaC10YXJnZXQtaGlzdG9yeS5zaG93e2Rpc3BsYXk6YmxvY2t9"
"Ci5oLXRoLWl0ZW17CiAgcGFkZGluZzo4cHggMTRweDtmb250LXNpemU6MTJweDtjb2xvcjp2YXIoLS10"
"eC1vbi1kYXJrLW11dGVkKTsKICBjdXJzb3I6cG9pbnRlcjt0cmFuc2l0aW9uOmJhY2tncm91bmQgLjE1"
"czsKICBmb250LWZhbWlseTonSUJNIFBsZXggTW9ubycsbW9ub3NwYWNlO2JvcmRlci1ib3R0b206MXB4"
"IHNvbGlkIHJnYmEoMjU1LDI1NSwyNTUsMC4wNCk7Cn0KLmgtdGgtaXRlbTpob3ZlcntiYWNrZ3JvdW5k"
"OnJnYmEoMjMwLDU3LDcwLDAuMSk7Y29sb3I6dmFyKC0td2hpdGUpfQouaC10aC1pdGVtOmxhc3QtY2hp"
"bGR7Ym9yZGVyLWJvdHRvbTpub25lfQouaC10aC1sYWJlbHtmb250LXNpemU6OXB4O2NvbG9yOnJnYmEo"
"MjU1LDI1NSwyNTUsMC4yNSk7bWFyZ2luLWJvdHRvbToycHg7bGV0dGVyLXNwYWNpbmc6MXB4fQoKQG1l"
"ZGlhKG1heC13aWR0aDo5MDBweCl7LnNpZGViYXJ7ZGlzcGxheTpub25lfS5kYXNoLWdyaWQuY29scy00"
"e2dyaWQtdGVtcGxhdGUtY29sdW1uczpyZXBlYXQoMiwxZnIpfX0KPC9zdHlsZT4KPC9oZWFkPgo8Ym9k"
"eT4KPGRpdiBjbGFzcz0iYXBwIj4KCjwhLS0gPT09PT09PT09PT09PT09PSBTSURFQkFSID09PT09PT09"
"PT09PT09PT0gLS0+Cjxhc2lkZSBjbGFzcz0ic2lkZWJhciI+CiAgPGRpdiBjbGFzcz0ic2lkZWJhci1z"
"Y3JvbGwiPgogICAgPGRpdiBjbGFzcz0icy1sb2dvIj4KICAgICAgPGRpdiBjbGFzcz0icy1sb2dvLW1h"
"cmsiPkg8L2Rpdj4KICAgICAgPGRpdj48ZGl2IGNsYXNzPSJzLWxvZ28tdGV4dCI+SEFSU0hBPC9kaXY+"
"PGRpdiBjbGFzcz0icy1sb2dvLXN1YiI+VkFQVCBTVUlURSB2Ny4wPC9kaXY+PC9kaXY+CiAgICA8L2Rp"
"dj4KCiAgICA8IS0tIFNFQVJDSCAtLT4KICAgIDxkaXYgY2xhc3M9InMtc2VhcmNoIj4KICAgICAgPHNw"
"YW4gY2xhc3M9InMtc2VhcmNoLWljb24iPvCflI08L3NwYW4+CiAgICAgIDxpbnB1dCB0eXBlPSJ0ZXh0"
"IiBjbGFzcz0icy1zZWFyY2gtaW5wdXQiIGlkPSJ0b29sLXNlYXJjaCIgcGxhY2Vob2xkZXI9IlNlYXJj"
"aCB0b29scy4uLiIgb25pbnB1dD0iZmlsdGVyVG9vbHModGhpcy52YWx1ZSkiPgogICAgPC9kaXY+Cgog"
"ICAgPCEtLSBORVRXT1JLIC0tPgogICAgPGRpdiBjbGFzcz0icy1zZWN0aW9uIG9wZW4iIGRhdGEtc2Vj"
"dGlvbj0ibmV0Ij4KICAgICAgPGRpdiBjbGFzcz0icy1zZWN0aW9uLWhlYWRlciIgb25jbGljaz0idG9n"
"Z2xlU2VjdGlvbih0aGlzKSI+CiAgICAgICAgPHNwYW4gY2xhc3M9InMtc2VjdGlvbi1pY29uIj7wn5Oh"
"PC9zcGFuPgogICAgICAgIDxzcGFuIGNsYXNzPSJzLXNlY3Rpb24tdGl0bGUiPk5ldHdvcms8L3NwYW4+"
"CiAgICAgICAgPHNwYW4gY2xhc3M9InMtc2VjdGlvbi1jb3VudCI+OTwvc3Bhbj4KICAgICAgICA8c3Bh"
"biBjbGFzcz0icy1zZWN0aW9uLWFycm93Ij7ilrw8L3NwYW4+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2"
"IGNsYXNzPSJzLXNlY3Rpb24tYm9keSI+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icy1uYXYiIG9uY2xp"
"Y2s9InJ1blRvb2woJ25tYXBfc2NhbicsdGhpcywnbmV0JykiIGRhdGEtbmFtZT0icG9ydCBzY2FubmVy"
"IG5tYXAiPjxzcGFuIGNsYXNzPSJpY28iPvCflI08L3NwYW4+PHNwYW4gY2xhc3M9ImxibCI+UG9ydCBT"
"Y2FubmVyPC9zcGFuPjxzcGFuIGNsYXNzPSJzLXRhZyByIj5DT1JFPC9zcGFuPjwvYnV0dG9uPgogICAg"
"ICAgIDxidXR0b24gY2xhc3M9InMtbmF2IiBvbmNsaWNrPSJydW5Ub29sKCdubWFwX3RvcDEwMCcsdGhp"
"cywnbmV0JykiIGRhdGEtbmFtZT0icXVpY2sgdG9wIDEwMCBmYXN0Ij48c3BhbiBjbGFzcz0iaWNvIj7i"
"mqE8L3NwYW4+PHNwYW4gY2xhc3M9ImxibCI+UXVpY2sgVG9wIDEwMDwvc3Bhbj48L2J1dHRvbj4KICAg"
"ICAgICA8YnV0dG9uIGNsYXNzPSJzLW5hdiIgb25jbGljaz0icnVuVG9vbCgnbm1hcF92dWxuJyx0aGlz"
"LCduZXQnKSIgZGF0YS1uYW1lPSJ2dWxuZXJhYmlsaXR5IGN2ZSBzY2FuIj48c3BhbiBjbGFzcz0iaWNv"
"Ij7wn5uhPC9zcGFuPjxzcGFuIGNsYXNzPSJsYmwiPlZ1bG4gU2Nhbjwvc3Bhbj48c3BhbiBjbGFzcz0i"
"cy10YWcgciI+Q1ZFPC9zcGFuPjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9InMtbmF2IiBv"
"bmNsaWNrPSJydW5Ub29sKCd1ZHBfc2NhbicsdGhpcywnbmV0JykiIGRhdGEtbmFtZT0idWRwIHNjYW4i"
"PjxzcGFuIGNsYXNzPSJpY28iPvCfk6E8L3NwYW4+PHNwYW4gY2xhc3M9ImxibCI+VURQIFNjYW48L3Nw"
"YW4+PC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icy1uYXYiIG9uY2xpY2s9InJ1blRvb2wo"
"J2ZpcmV3YWxsX2RldGVjdCcsdGhpcywnbmV0JykiIGRhdGEtbmFtZT0iZmlyZXdhbGwgZGV0ZWN0IHdh"
"ZiI+PHNwYW4gY2xhc3M9ImljbyI+8J+nsTwvc3Bhbj48c3BhbiBjbGFzcz0ibGJsIj5GaXJld2FsbCBE"
"ZXRlY3Q8L3NwYW4+PC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icy1uYXYiIG9uY2xpY2s9"
"InJ1blRvb2woJ3NtYl9lbnVtJyx0aGlzLCduZXQnKSIgZGF0YS1uYW1lPSJzbWIgZW51bSBzaGFyZSI+"
"PHNwYW4gY2xhc3M9ImljbyI+8J+Tgjwvc3Bhbj48c3BhbiBjbGFzcz0ibGJsIj5TTUIgRW51bTwvc3Bh"
"bj48L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzLW5hdiIgb25jbGljaz0icnVuVG9vbCgn"
"c25tcF9jaGVjaycsdGhpcywnbmV0JykiIGRhdGEtbmFtZT0ic25tcCBjaGVjayBjb21tdW5pdHkiPjxz"
"cGFuIGNsYXNzPSJpY28iPvCfk4o8L3NwYW4+PHNwYW4gY2xhc3M9ImxibCI+U05NUCBDaGVjazwvc3Bh"
"bj48L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzLW5hdiIgb25jbGljaz0icnVuVG9vbCgn"
"YmFubmVyX2dyYWInLHRoaXMsJ25ldCcpIiBkYXRhLW5hbWU9ImJhbm5lciBncmFiIHNlcnZpY2UgdmVy"
"c2lvbiI+PHNwYW4gY2xhc3M9ImljbyI+8J+Ptzwvc3Bhbj48c3BhbiBjbGFzcz0ibGJsIj5CYW5uZXIg"
"R3JhYjwvc3Bhbj48L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzLW5hdiIgb25jbGljaz0i"
"cnVuVG9vbCgnYXJwX3NjYW4nLHRoaXMsJ25ldCcpIiBkYXRhLW5hbWU9ImFycCBzY2FuIGxvY2FsIj48"
"c3BhbiBjbGFzcz0iaWNvIj7wn5OLPC9zcGFuPjxzcGFuIGNsYXNzPSJsYmwiPkFSUCBTY2FuPC9zcGFu"
"PjwvYnV0dG9uPgogICAgICA8L2Rpdj4KICAgIDwvZGl2PgoKICAgIDwhLS0gV0VCIC0tPgogICAgPGRp"
"diBjbGFzcz0icy1zZWN0aW9uIG9wZW4iIGRhdGEtc2VjdGlvbj0id2ViIj4KICAgICAgPGRpdiBjbGFz"
"cz0icy1zZWN0aW9uLWhlYWRlciIgb25jbGljaz0idG9nZ2xlU2VjdGlvbih0aGlzKSI+CiAgICAgICAg"
"PHNwYW4gY2xhc3M9InMtc2VjdGlvbi1pY29uIj7wn4yQPC9zcGFuPgogICAgICAgIDxzcGFuIGNsYXNz"
"PSJzLXNlY3Rpb24tdGl0bGUiPldlYjwvc3Bhbj4KICAgICAgICA8c3BhbiBjbGFzcz0icy1zZWN0aW9u"
"LWNvdW50Ij4xMDwvc3Bhbj4KICAgICAgICA8c3BhbiBjbGFzcz0icy1zZWN0aW9uLWFycm93Ij7ilrw8"
"L3NwYW4+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJzLXNlY3Rpb24tYm9keSI+CiAgICAg"
"ICAgPGJ1dHRvbiBjbGFzcz0icy1uYXYiIG9uY2xpY2s9InJ1blRvb2woJ3NxbG1hcF9jaGVjaycsdGhp"
"cywnd2ViJykiIGRhdGEtbmFtZT0ic3FsIGluamVjdGlvbiBzcWxpIHNxbG1hcCI+PHNwYW4gY2xhc3M9"
"ImljbyI+8J+SiTwvc3Bhbj48c3BhbiBjbGFzcz0ibGJsIj5TUUwgSW5qZWN0aW9uPC9zcGFuPjxzcGFu"
"IGNsYXNzPSJzLXRhZyByIj5DUklUPC9zcGFuPjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9"
"InMtbmF2IiBvbmNsaWNrPSJydW5Ub29sKCd4c3Nfc2NhbicsdGhpcywnd2ViJykiIGRhdGEtbmFtZT0i"
"eHNzIGNyb3NzIHNpdGUgc2NyaXB0aW5nIj48c3BhbiBjbGFzcz0iaWNvIj7imqA8L3NwYW4+PHNwYW4g"
"Y2xhc3M9ImxibCI+WFNTIFNjYW5uZXI8L3NwYW4+PC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFz"
"cz0icy1uYXYiIG9uY2xpY2s9InJ1blRvb2woJ25pa3RvX3NjYW4nLHRoaXMsJ3dlYicpIiBkYXRhLW5h"
"bWU9Im5pa3RvIHdlYiBzY2FuIj48c3BhbiBjbGFzcz0iaWNvIj7wn4yQPC9zcGFuPjxzcGFuIGNsYXNz"
"PSJsYmwiPk5pa3RvIFNjYW48L3NwYW4+PC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icy1u"
"YXYiIG9uY2xpY2s9InJ1blRvb2woJ2hlYWRlcl9jaGVjaycsdGhpcywnd2ViJykiIGRhdGEtbmFtZT0i"
"aGVhZGVyIGF1ZGl0IGh0dHAgc2VjdXJpdHkiPjxzcGFuIGNsYXNzPSJpY28iPvCfk4s8L3NwYW4+PHNw"
"YW4gY2xhc3M9ImxibCI+SGVhZGVyIEF1ZGl0PC9zcGFuPjwvYnV0dG9uPgogICAgICAgIDxidXR0b24g"
"Y2xhc3M9InMtbmF2IiBvbmNsaWNrPSJydW5Ub29sKCdzc2xfY2hlY2snLHRoaXMsJ3dlYicpIiBkYXRh"
"LW5hbWU9InNzbCB0bHMgY2VydGlmaWNhdGUgaHR0cHMiPjxzcGFuIGNsYXNzPSJpY28iPvCflJI8L3Nw"
"YW4+PHNwYW4gY2xhc3M9ImxibCI+U1NML1RMUyBDaGVjazwvc3Bhbj48L2J1dHRvbj4KICAgICAgICA8"
"YnV0dG9uIGNsYXNzPSJzLW5hdiIgb25jbGljaz0icnVuVG9vbCgnd2FmX2RldGVjdCcsdGhpcywnd2Vi"
"JykiIGRhdGEtbmFtZT0id2FmIHdlYiBhcHBsaWNhdGlvbiBmaXJld2FsbCI+PHNwYW4gY2xhc3M9Imlj"
"byI+8J+boTwvc3Bhbj48c3BhbiBjbGFzcz0ibGJsIj5XQUYgRGV0ZWN0PC9zcGFuPjwvYnV0dG9uPgog"
"ICAgICAgIDxidXR0b24gY2xhc3M9InMtbmF2IiBvbmNsaWNrPSJydW5Ub29sKCdjb3JzX2NoZWNrJyx0"
"aGlzLCd3ZWInKSIgZGF0YS1uYW1lPSJjb3JzIGNyb3NzIG9yaWdpbiI+PHNwYW4gY2xhc3M9ImljbyI+"
"8J+Ulzwvc3Bhbj48c3BhbiBjbGFzcz0ibGJsIj5DT1JTIENoZWNrPC9zcGFuPjwvYnV0dG9uPgogICAg"
"ICAgIDxidXR0b24gY2xhc3M9InMtbmF2IiBvbmNsaWNrPSJydW5Ub29sKCdkaXJfZW51bScsdGhpcywn"
"d2ViJykiIGRhdGEtbmFtZT0iZGlyZWN0b3J5IGVudW1lcmF0aW9uIGJydXRlIGRpcmJ1c3RlciI+PHNw"
"YW4gY2xhc3M9ImljbyI+8J+TgTwvc3Bhbj48c3BhbiBjbGFzcz0ibGJsIj5EaXJlY3RvcnkgRW51bTwv"
"c3Bhbj48L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzLW5hdiIgb25jbGljaz0icnVuVG9v"
"bCgnY21zX2RldGVjdCcsdGhpcywnd2ViJykiIGRhdGEtbmFtZT0iY21zIGRldGVjdCB3b3JkcHJlc3Mg"
"am9vbWxhIGRydXBhbCI+PHNwYW4gY2xhc3M9ImljbyI+8J+Plzwvc3Bhbj48c3BhbiBjbGFzcz0ibGJs"
"Ij5DTVMgRGV0ZWN0PC9zcGFuPjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9InMtbmF2IiBv"
"bmNsaWNrPSJydW5Ub29sKCdhZG1pbl9maW5kZXInLHRoaXMsJ3dlYicpIiBkYXRhLW5hbWU9ImFkbWlu"
"IGZpbmRlciBwYW5lbCBsb2dpbiI+PHNwYW4gY2xhc3M9ImljbyI+8J+UkTwvc3Bhbj48c3BhbiBjbGFz"
"cz0ibGJsIj5BZG1pbiBGaW5kZXI8L3NwYW4+PC9idXR0b24+CiAgICAgIDwvZGl2PgogICAgPC9kaXY+"
"CgogICAgPCEtLSBJTkZSQVNUUlVDVFVSRSAtLT4KICAgIDxkaXYgY2xhc3M9InMtc2VjdGlvbiIgZGF0"
"YS1zZWN0aW9uPSJpbmYiPgogICAgICA8ZGl2IGNsYXNzPSJzLXNlY3Rpb24taGVhZGVyIiBvbmNsaWNr"
"PSJ0b2dnbGVTZWN0aW9uKHRoaXMpIj4KICAgICAgICA8c3BhbiBjbGFzcz0icy1zZWN0aW9uLWljb24i"
"PvCflqU8L3NwYW4+CiAgICAgICAgPHNwYW4gY2xhc3M9InMtc2VjdGlvbi10aXRsZSI+SW5mcmFzdHJ1"
"Y3R1cmU8L3NwYW4+CiAgICAgICAgPHNwYW4gY2xhc3M9InMtc2VjdGlvbi1jb3VudCI+Njwvc3Bhbj4K"
"ICAgICAgICA8c3BhbiBjbGFzcz0icy1zZWN0aW9uLWFycm93Ij7ilrw8L3NwYW4+CiAgICAgIDwvZGl2"
"PgogICAgICA8ZGl2IGNsYXNzPSJzLXNlY3Rpb24tYm9keSI+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0i"
"cy1uYXYiIG9uY2xpY2s9InJ1blRvb2woJ3NzaF9hdWRpdCcsdGhpcywnaW5mJykiIGRhdGEtbmFtZT0i"
"c3NoIGF1ZGl0IGtleSI+PHNwYW4gY2xhc3M9ImljbyI+8J+UkDwvc3Bhbj48c3BhbiBjbGFzcz0ibGJs"
"Ij5TU0ggQXVkaXQ8L3NwYW4+PC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icy1uYXYiIG9u"
"Y2xpY2s9InJ1blRvb2woJ2Z0cF9jaGVjaycsdGhpcywnaW5mJykiIGRhdGEtbmFtZT0iZnRwIGFub255"
"bW91cyBjaGVjayI+PHNwYW4gY2xhc3M9ImljbyI+8J+TpDwvc3Bhbj48c3BhbiBjbGFzcz0ibGJsIj5G"
"VFAgQ2hlY2s8L3NwYW4+PC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icy1uYXYiIG9uY2xp"
"Y2s9InJ1blRvb2woJ3JkcF9jaGVjaycsdGhpcywnaW5mJykiIGRhdGEtbmFtZT0icmRwIHJlbW90ZSBk"
"ZXNrdG9wIGJsdWVrZWVwIj48c3BhbiBjbGFzcz0iaWNvIj7wn5alPC9zcGFuPjxzcGFuIGNsYXNzPSJs"
"YmwiPlJEUCBDaGVjazwvc3Bhbj48L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzLW5hdiIg"
"b25jbGljaz0icnVuVG9vbCgnZGJfZXhwb3NlJyx0aGlzLCdpbmYnKSIgZGF0YS1uYW1lPSJkYXRhYmFz"
"ZSBleHBvc3VyZSBteXNxbCBwb3N0Z3JlcyByZWRpcyBtb25nbyI+PHNwYW4gY2xhc3M9ImljbyI+8J+X"
"hDwvc3Bhbj48c3BhbiBjbGFzcz0ibGJsIj5EQiBFeHBvc3VyZTwvc3Bhbj48L2J1dHRvbj4KICAgICAg"
"ICA8YnV0dG9uIGNsYXNzPSJzLW5hdiIgb25jbGljaz0icnVuVG9vbCgnZG9ja2VyX2NoZWNrJyx0aGlz"
"LCdpbmYnKSIgZGF0YS1uYW1lPSJkb2NrZXIgY29udGFpbmVyIGFwaSI+PHNwYW4gY2xhc3M9ImljbyI+"
"8J+Qszwvc3Bhbj48c3BhbiBjbGFzcz0ibGJsIj5Eb2NrZXIgQ2hlY2s8L3NwYW4+PC9idXR0b24+CiAg"
"ICAgICAgPGJ1dHRvbiBjbGFzcz0icy1uYXYiIG9uY2xpY2s9InJ1blRvb2woJ2s4c19jaGVjaycsdGhp"
"cywnaW5mJykiIGRhdGEtbmFtZT0ia3ViZXJuZXRlcyBrOHMgY2x1c3RlciI+PHNwYW4gY2xhc3M9Imlj"
"byI+4pi4PC9zcGFuPjxzcGFuIGNsYXNzPSJsYmwiPks4cyBDaGVjazwvc3Bhbj48L2J1dHRvbj4KICAg"
"ICAgPC9kaXY+CiAgICA8L2Rpdj4KCiAgICA8IS0tIE5VQ0xFSSAtLT4KICAgIDxkaXYgY2xhc3M9InMt"
"c2VjdGlvbiIgZGF0YS1zZWN0aW9uPSJudWMiPgogICAgICA8ZGl2IGNsYXNzPSJzLXNlY3Rpb24taGVh"
"ZGVyIiBvbmNsaWNrPSJ0b2dnbGVTZWN0aW9uKHRoaXMpIj4KICAgICAgICA8c3BhbiBjbGFzcz0icy1z"
"ZWN0aW9uLWljb24iPuKYojwvc3Bhbj4KICAgICAgICA8c3BhbiBjbGFzcz0icy1zZWN0aW9uLXRpdGxl"
"Ij5OdWNsZWk8L3NwYW4+CiAgICAgICAgPHNwYW4gY2xhc3M9InMtc2VjdGlvbi1jb3VudCI+Njwvc3Bh"
"bj4KICAgICAgICA8c3BhbiBjbGFzcz0icy1zZWN0aW9uLWFycm93Ij7ilrw8L3NwYW4+CiAgICAgIDwv"
"ZGl2PgogICAgICA8ZGl2IGNsYXNzPSJzLXNlY3Rpb24tYm9keSI+CiAgICAgICAgPGJ1dHRvbiBjbGFz"
"cz0icy1uYXYiIG9uY2xpY2s9InJ1blRvb2woJ251Y2xlaV9mdWxsJyx0aGlzLCd3ZWInKSIgZGF0YS1u"
"YW1lPSJudWNsZWkgZnVsbCBzY2FuIGFsbCB0ZW1wbGF0ZXMiPjxzcGFuIGNsYXNzPSJpY28iPuKYojwv"
"c3Bhbj48c3BhbiBjbGFzcz0ibGJsIj5GdWxsIFNjYW48L3NwYW4+PHNwYW4gY2xhc3M9InMtdGFnIHIi"
"PkNPUkU8L3NwYW4+PC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icy1uYXYiIG9uY2xpY2s9"
"InJ1blRvb2woJ251Y2xlaV9jdmUnLHRoaXMsJ3dlYicpIiBkYXRhLW5hbWU9Im51Y2xlaSBjdmUgdnVs"
"bmVyYWJpbGl0eSI+PHNwYW4gY2xhc3M9ImljbyI+8J+UpTwvc3Bhbj48c3BhbiBjbGFzcz0ibGJsIj5D"
"VkUgU2Nhbjwvc3Bhbj48c3BhbiBjbGFzcz0icy10YWcgciI+Q1ZFPC9zcGFuPjwvYnV0dG9uPgogICAg"
"ICAgIDxidXR0b24gY2xhc3M9InMtbmF2IiBvbmNsaWNrPSJydW5Ub29sKCdudWNsZWlfY3JpdGljYWwn"
"LHRoaXMsJ3dlYicpIiBkYXRhLW5hbWU9Im51Y2xlaSBjcml0aWNhbCBoaWdoIHNldmVyaXR5Ij48c3Bh"
"biBjbGFzcz0iaWNvIj7wn5qoPC9zcGFuPjxzcGFuIGNsYXNzPSJsYmwiPkNyaXRpY2FsL0hpZ2g8L3Nw"
"YW4+PC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icy1uYXYiIG9uY2xpY2s9InJ1blRvb2wo"
"J251Y2xlaV9taXNjb25maWcnLHRoaXMsJ3dlYicpIiBkYXRhLW5hbWU9Im51Y2xlaSBtaXNjb25maWd1"
"cmF0aW9uIGV4cG9zZWQiPjxzcGFuIGNsYXNzPSJpY28iPuKamTwvc3Bhbj48c3BhbiBjbGFzcz0ibGJs"
"Ij5NaXNjb25maWcgU2Nhbjwvc3Bhbj48L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzLW5h"
"diIgb25jbGljaz0icnVuVG9vbCgnbnVjbGVpX3RlY2gnLHRoaXMsJ3dlYicpIiBkYXRhLW5hbWU9Im51"
"Y2xlaSB0ZWNobm9sb2d5IGRldGVjdCBmaW5nZXJwcmludCI+PHNwYW4gY2xhc3M9ImljbyI+8J+UrDwv"
"c3Bhbj48c3BhbiBjbGFzcz0ibGJsIj5UZWNoIERldGVjdDwvc3Bhbj48L2J1dHRvbj4KICAgICAgICA8"
"YnV0dG9uIGNsYXNzPSJzLW5hdiIgb25jbGljaz0icnVuVG9vbCgnbnVjbGVpX25ldHdvcmsnLHRoaXMs"
"J2luZicpIiBkYXRhLW5hbWU9Im51Y2xlaSBuZXR3b3JrIHByb3RvY29sIj48c3BhbiBjbGFzcz0iaWNv"
"Ij7wn4yQPC9zcGFuPjxzcGFuIGNsYXNzPSJsYmwiPk5ldHdvcmsgU2Nhbjwvc3Bhbj48L2J1dHRvbj4K"
"ICAgICAgPC9kaXY+CiAgICA8L2Rpdj4KCiAgICA8IS0tIFJFQ09OIC0tPgogICAgPGRpdiBjbGFzcz0i"
"cy1zZWN0aW9uIiBkYXRhLXNlY3Rpb249InJlYyI+CiAgICAgIDxkaXYgY2xhc3M9InMtc2VjdGlvbi1o"
"ZWFkZXIiIG9uY2xpY2s9InRvZ2dsZVNlY3Rpb24odGhpcykiPgogICAgICAgIDxzcGFuIGNsYXNzPSJz"
"LXNlY3Rpb24taWNvbiI+8J+VtTwvc3Bhbj4KICAgICAgICA8c3BhbiBjbGFzcz0icy1zZWN0aW9uLXRp"
"dGxlIj5SZWNvbjwvc3Bhbj4KICAgICAgICA8c3BhbiBjbGFzcz0icy1zZWN0aW9uLWNvdW50Ij43PC9z"
"cGFuPgogICAgICAgIDxzcGFuIGNsYXNzPSJzLXNlY3Rpb24tYXJyb3ciPuKWvDwvc3Bhbj4KICAgICAg"
"PC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9InMtc2VjdGlvbi1ib2R5Ij4KICAgICAgICA8YnV0dG9uIGNs"
"YXNzPSJzLW5hdiIgb25jbGljaz0icnVuVG9vbCgnd2hvaXMnLHRoaXMsJ3JlYycpIiBkYXRhLW5hbWU9"
"Indob2lzIGRvbWFpbiByZWdpc3RyYXRpb24iPjxzcGFuIGNsYXNzPSJpY28iPvCfjI08L3NwYW4+PHNw"
"YW4gY2xhc3M9ImxibCI+V0hPSVM8L3NwYW4+PC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0i"
"cy1uYXYiIG9uY2xpY2s9InJ1blRvb2woJ2Ruc19sb29rdXAnLHRoaXMsJ3JlYycpIiBkYXRhLW5hbWU9"
"ImRucyBsb29rdXAgcmVjb3JkcyI+PHNwYW4gY2xhc3M9ImljbyI+8J+ToTwvc3Bhbj48c3BhbiBjbGFz"
"cz0ibGJsIj5ETlMgTG9va3VwPC9zcGFuPjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9InMt"
"bmF2IiBvbmNsaWNrPSJydW5Ub29sKCdzdWJkb21haW5fZW51bScsdGhpcywncmVjJykiIGRhdGEtbmFt"
"ZT0ic3ViZG9tYWluIGVudW1lcmF0aW9uIj48c3BhbiBjbGFzcz0iaWNvIj7wn5SOPC9zcGFuPjxzcGFu"
"IGNsYXNzPSJsYmwiPlN1YmRvbWFpbiBFbnVtPC9zcGFuPjwvYnV0dG9uPgogICAgICAgIDxidXR0b24g"
"Y2xhc3M9InMtbmF2IiBvbmNsaWNrPSJydW5Ub29sKCd0cmFjZXJvdXRlJyx0aGlzLCdyZWMnKSIgZGF0"
"YS1uYW1lPSJ0cmFjZXJvdXRlIGhvcHMiPjxzcGFuIGNsYXNzPSJpY28iPvCfm6Q8L3NwYW4+PHNwYW4g"
"Y2xhc3M9ImxibCI+VHJhY2Vyb3V0ZTwvc3Bhbj48L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNz"
"PSJzLW5hdiIgb25jbGljaz0icnVuVG9vbCgnbmV0d29ya19zY2FuJyx0aGlzLCdyZWMnKSIgZGF0YS1u"
"YW1lPSJsb2NhbCBuZXR3b3JrIHNjYW4gZGlzY292ZXIiPjxzcGFuIGNsYXNzPSJpY28iPvCfk7Y8L3Nw"
"YW4+PHNwYW4gY2xhc3M9ImxibCI+TG9jYWwgTmV0d29yazwvc3Bhbj48L2J1dHRvbj4KICAgICAgICA8"
"YnV0dG9uIGNsYXNzPSJzLW5hdiIgb25jbGljaz0icnVuVG9vbCgnbXlfaXAnLHRoaXMsJ3JlYycpIiBk"
"YXRhLW5hbWU9Im15IGlwIGFkZHJlc3MgcHVibGljIj48c3BhbiBjbGFzcz0iaWNvIj7wn4+gPC9zcGFu"
"PjxzcGFuIGNsYXNzPSJsYmwiPk15IElQPC9zcGFuPjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xh"
"c3M9InMtbmF2IiBvbmNsaWNrPSJydW5Ub29sKCdzeXN0ZW1faW5mbycsdGhpcywncmVjJykiIGRhdGEt"
"bmFtZT0ic3lzdGVtIGluZm8gY3B1IHJhbSBvcyI+PHNwYW4gY2xhc3M9ImljbyI+8J+Suzwvc3Bhbj48"
"c3BhbiBjbGFzcz0ibGJsIj5TeXN0ZW0gSW5mbzwvc3Bhbj48L2J1dHRvbj4KICAgICAgPC9kaXY+CiAg"
"ICA8L2Rpdj4KICA8L2Rpdj4KICA8ZGl2IGNsYXNzPSJzLWZvb3RlciI+CiAgICA8ZGl2IGNsYXNzPSJz"
"LWF2YXRhciI+SEE8L2Rpdj4KICAgIDxkaXY+PGRpdiBjbGFzcz0icy11bmFtZSI+SEFSU0hBPC9kaXY+"
"PGRpdiBjbGFzcz0icy11cm9sZSI+TGV2ZWwgNSDCtyAzOCBUb29scyBBcm1lZDwvZGl2PjwvZGl2Pgog"
"IDwvZGl2Pgo8L2FzaWRlPgoKPCEtLSA9PT09PT09PT09PT09PT09IE1BSU4gPT09PT09PT09PT09PT09"
"PSAtLT4KPGRpdiBjbGFzcz0ibWFpbiI+CiAgPGhlYWRlciBjbGFzcz0iaGVhZGVyIj4KICAgIDxkaXYg"
"Y2xhc3M9ImgtbGVmdCI+CiAgICAgIDxkaXYgY2xhc3M9ImgtdGl0bGUiPlZBUFQgRGFzaGJvYXJkPC9k"
"aXY+CiAgICAgIDxkaXYgY2xhc3M9Imgtc2VwIj48L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0iaC10YXJn"
"ZXQiIHN0eWxlPSJwb3NpdGlvbjpyZWxhdGl2ZSI+CiAgICAgICAgPGRpdiBjbGFzcz0iaC10YXJnZXQt"
"cHJlIj5UQVJHRVQ8L2Rpdj4KICAgICAgICA8aW5wdXQgdHlwZT0idGV4dCIgaWQ9InRhcmdldC1pbnB1"
"dCIgY2xhc3M9ImgtdGFyZ2V0LWlucHV0IiBwbGFjZWhvbGRlcj0iRW50ZXIgSVAsIGRvbWFpbiwgb3Ig"
"VVJMLi4uIiBvbmZvY3VzPSJzaG93VGFyZ2V0SGlzdG9yeSgpIiBvbmlucHV0PSJzaG93VGFyZ2V0SGlz"
"dG9yeSgpIiBhdXRvY29tcGxldGU9Im9mZiI+CiAgICAgICAgPGRpdiBjbGFzcz0iaC10YXJnZXQtaGlz"
"dG9yeSIgaWQ9InRhcmdldC1oaXN0b3J5Ij48L2Rpdj4KICAgICAgPC9kaXY+CiAgICA8L2Rpdj4KICAg"
"IDxkaXYgY2xhc3M9ImgtcmlnaHQiPgogICAgICA8ZGl2IGNsYXNzPSJoLW1pbmktc3RhdHMiIGlkPSJo"
"LW1pbmktc3RhdHMiPgogICAgICAgIDxzcGFuIGNsYXNzPSJoLW1pbmktc3RhdCIgdGl0bGU9IlNjYW5z"
"Ij7wn5SNIDxzdHJvbmcgaWQ9ImhtLXNjYW5zIj4wPC9zdHJvbmc+PC9zcGFuPgogICAgICAgIDxzcGFu"
"IGNsYXNzPSJoLW1pbmktc3RhdCIgdGl0bGU9IlBvcnRzIj7wn5OhIDxzdHJvbmcgaWQ9ImhtLXBvcnRz"
"Ij4wPC9zdHJvbmc+PC9zcGFuPgogICAgICAgIDxzcGFuIGNsYXNzPSJoLW1pbmktc3RhdCIgdGl0bGU9"
"IlRocmVhdHMiPuKaoCA8c3Ryb25nIGlkPSJobS10aHJlYXRzIj4wPC9zdHJvbmc+PC9zcGFuPgogICAg"
"ICA8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0iaC1zdGF0dXMiPjxzcGFuIGNsYXNzPSJkb3QiPjwvc3Bh"
"bj5PTkxJTkU8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0iaC1jbG9jayIgaWQ9ImNsb2NrIj48L2Rpdj4K"
"ICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuLXJlcG9ydCIgb25jbGljaz0ib3BlblJlcG9ydCgpIj7wn5OE"
"IFJlcG9ydDwvYnV0dG9uPgogICAgPC9kaXY+CiAgPC9oZWFkZXI+CiAgPCEtLSBNSU5JIFBST0dSRVNT"
"IEJBUiAtLT4KICA8ZGl2IGNsYXNzPSJoLW1pbmktcHJvZ3Jlc3MiIGlkPSJoLW1pbmktcHJvZ3Jlc3Mi"
"PjxkaXYgY2xhc3M9ImgtbWluaS1iYXIiIGlkPSJoLW1pbmktYmFyIj48L2Rpdj48L2Rpdj4KICA8bmF2"
"IGNsYXNzPSJ0YWItbmF2Ij4KICAgIDxidXR0b24gY2xhc3M9InRhYi1idG4gYWN0aXZlIiBvbmNsaWNr"
"PSJzd2l0Y2hUYWIoJ3Rlcm1pbmFsJyx0aGlzKSI+VGVybWluYWw8L2J1dHRvbj4KICAgIDxidXR0b24g"
"Y2xhc3M9InRhYi1idG4iIG9uY2xpY2s9InN3aXRjaFRhYigncG9ydHMnLHRoaXMpIj5Qb3J0cyA8c3Bh"
"biBjbGFzcz0idGFiLWJhZGdlIiBpZD0icG9ydC1iYWRnZSI+MDwvc3Bhbj48L2J1dHRvbj4KICAgIDxi"
"dXR0b24gY2xhc3M9InRhYi1idG4iIG9uY2xpY2s9InN3aXRjaFRhYigndGhyZWF0cycsdGhpcykiPlRo"
"cmVhdHMgPHNwYW4gY2xhc3M9InRhYi1iYWRnZSIgaWQ9InRocmVhdC1iYWRnZSI+MDwvc3Bhbj48L2J1"
"dHRvbj4KICAgIDxidXR0b24gY2xhc3M9InRhYi1idG4iIG9uY2xpY2s9InN3aXRjaFRhYigncmlzaycs"
"dGhpcykiPlJpc2sgQW5hbHlzaXM8L2J1dHRvbj4KICAgIDxidXR0b24gY2xhc3M9InRhYi1idG4iIG9u"
"Y2xpY2s9InN3aXRjaFRhYigndGdyYXBoJyx0aGlzKSI+VGhyZWF0IEdyYXBoPC9idXR0b24+CiAgICA8"
"YnV0dG9uIGNsYXNzPSJ0YWItYnRuIiBvbmNsaWNrPSJzd2l0Y2hUYWIoJ3NjYW5zdGF0dXMnLHRoaXMp"
"Ij5TY2FuIFN0YXR1cyA8c3BhbiBjbGFzcz0idGFiLWJhZGdlIiBpZD0ic2Nhbi1zdGF0dXMtYmFkZ2Ui"
"PuKXjzwvc3Bhbj48L2J1dHRvbj4KICA8L25hdj4KCiAgPGRpdiBjbGFzcz0iY29udGVudCI+CiAgICA8"
"IS0tIFRFUk1JTkFMIC0tPgogICAgPGRpdiBjbGFzcz0idGFiLXBhbmUgYWN0aXZlIiBpZD0icGFuZS10"
"ZXJtaW5hbCI+CiAgICAgIDxkaXYgY2xhc3M9InRlcm1pbmFsLWNhcmQiPgogICAgICAgIDxkaXYgY2xh"
"c3M9InRlcm0taGVhZGVyIj4KICAgICAgICAgIDxkaXYgY2xhc3M9InRlcm0tZG90cyI+PHNwYW4gY2xh"
"c3M9ImQxIj48L3NwYW4+PHNwYW4gY2xhc3M9ImQyIj48L3NwYW4+PHNwYW4gY2xhc3M9ImQzIj48L3Nw"
"YW4+PC9kaXY+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJ0ZXJtLXRpdGxlIj5IQVJTSEEgdjcuMCDigJQg"
"T1VUUFVUPC9kaXY+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJ0ZXJtLWFjdGlvbnMiPjxidXR0b24gY2xh"
"c3M9InRlcm0tYWN0IiBvbmNsaWNrPSJjb3B5T3V0cHV0KCkiPkNPUFk8L2J1dHRvbj48YnV0dG9uIGNs"
"YXNzPSJ0ZXJtLWFjdCIgb25jbGljaz0iY2xlYXJUZXJtaW5hbCgpIj5DTEVBUjwvYnV0dG9uPjwvZGl2"
"PgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImxvYWRpbmctYmFyIiBpZD0ibG9hZGlu"
"Zy1iYXIiPjwvZGl2PgogICAgICAgIDxkaXYgaWQ9InRlcm1pbmFsLW91dHB1dCI+CiAgICAgICAgICA8"
"ZGl2IGNsYXNzPSJ0bCBoZHIiPi8vIEhBUlNIQSB2Ny4wIOKAlCBXRUIgKyBORVRXT1JLICsgSU5GUkFT"
"VFJVQ1RVUkUgVkFQVCBTVUlURTwvZGl2PgogICAgICAgICAgPGRpdiBjbGFzcz0idGwgcHJvbXB0Ij5o"
"YXJzaGFAa2FsaTp+JCA8c3BhbiBjbGFzcz0iYmxpbmsiPnw8L3NwYW4+PC9kaXY+CiAgICAgICAgICA8"
"ZGl2IGNsYXNzPSJ0bCBpbmZvIj5bIFdFQiAgICAgXSBTUUwgSW5qZWN0aW9uLCBYU1MsIFdBRiwgQ09S"
"UywgQWRtaW4gRmluZGVyLCBDTVMsIFNTTDwvZGl2PgogICAgICAgICAgPGRpdiBjbGFzcz0idGwgaW5m"
"byI+WyBORVRXT1JLIF0gUG9ydCBTY2FuLCBVRFAsIEZpcmV3YWxsLCBTTUIsIFNOTVAsIEJhbm5lciwg"
"QVJQPC9kaXY+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bCBpbmZvIj5bIElORlJBICAgXSBTU0gsIEZU"
"UCwgUkRQLCBEQiBFeHBvc3VyZSwgRG9ja2VyLCBLOHMsIENWRSBTY2FuPC9kaXY+CiAgICAgICAgICA8"
"ZGl2IGNsYXNzPSJ0bCByZXN1bHQiPlsgUkVBRFkgICBdIFNlbGVjdCBhIHRvb2wgZnJvbSBzaWRlYmFy"
"IGFuZCBlbnRlciB0YXJnZXQgdG8gYmVnaW4uPC9kaXY+CiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2"
"PgogICAgICA8ZGl2IGNsYXNzPSJkYXNoLWdyaWQgY29scy00IiBzdHlsZT0ibWFyZ2luLXRvcDoyMHB4"
"Ij4KICAgICAgICA8ZGl2IGNsYXNzPSJjYXJkIj48ZGl2IGNsYXNzPSJjYXJkLXN1YnRpdGxlIj5Ub3Rh"
"bCBTY2FuczwvZGl2PjxkaXYgY2xhc3M9InN0YXQtbnVtIGJyYW5kIiBpZD0ic3RhdC1zY2FucyI+MDwv"
"ZGl2PjxkaXYgY2xhc3M9InN0YXQtYmFyLXdyYXAiPjxkaXYgY2xhc3M9InN0YXQtYmFyIj48ZGl2IGNs"
"YXNzPSJzdGF0LWJhci1maWxsIGJyYW5kIiBpZD0ic2Nhbi1iYXIiIHN0eWxlPSJ3aWR0aDowJSI+PC9k"
"aXY+PC9kaXY+PC9kaXY+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iY2FyZCI+PGRpdiBjbGFzcz0i"
"Y2FyZC1zdWJ0aXRsZSI+T3BlbiBQb3J0czwvZGl2PjxkaXYgY2xhc3M9InN0YXQtbnVtIG9yYW5nZSIg"
"aWQ9InN0YXQtcG9ydHMiPjA8L2Rpdj48ZGl2IGNsYXNzPSJzdGF0LWJhci13cmFwIj48ZGl2IGNsYXNz"
"PSJzdGF0LWJhciI+PGRpdiBjbGFzcz0ic3RhdC1iYXItZmlsbCBvcmFuZ2UiIGlkPSJwb3J0LWJhciIg"
"c3R5bGU9IndpZHRoOjAlIj48L2Rpdj48L2Rpdj48L2Rpdj48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNz"
"PSJjYXJkIj48ZGl2IGNsYXNzPSJjYXJkLXN1YnRpdGxlIj5UaHJlYXRzIEZvdW5kPC9kaXY+PGRpdiBj"
"bGFzcz0ic3RhdC1udW0gcmVkIiBpZD0ic3RhdC10aHJlYXRzIj4wPC9kaXY+PGRpdiBjbGFzcz0ic3Rh"
"dC1iYXItd3JhcCI+PGRpdiBjbGFzcz0ic3RhdC1iYXIiPjxkaXYgY2xhc3M9InN0YXQtYmFyLWZpbGwg"
"cmVkIiBpZD0idGhyZWF0LWJhciIgc3R5bGU9IndpZHRoOjAlIj48L2Rpdj48L2Rpdj48L2Rpdj48L2Rp"
"dj4KICAgICAgICA8ZGl2IGNsYXNzPSJjYXJkIj48ZGl2IGNsYXNzPSJjYXJkLXN1YnRpdGxlIj5MYXN0"
"IFRvb2w8L2Rpdj48ZGl2IHN0eWxlPSJmb250LXNpemU6MTRweDtmb250LXdlaWdodDo3MDA7Y29sb3I6"
"dmFyKC0tdHgtZGFyayk7bWFyZ2luLXRvcDo0cHgiIGlkPSJzdGF0LWxhc3QtdG9vbCI+4oCUPC9kaXY+"
"PGRpdiBjbGFzcz0ic3RhdC1zdWIiIGlkPSJzdGF0LWxhc3QtdGltZSI+QXdhaXRpbmcgc2NhbjwvZGl2"
"PjwvZGl2PgogICAgICA8L2Rpdj4KICAgIDwvZGl2PgoKICAgIDwhLS0gUE9SVFMgLS0+CiAgICA8ZGl2"
"IGNsYXNzPSJ0YWItcGFuZSIgaWQ9InBhbmUtcG9ydHMiPjxkaXYgaWQ9InBvcnQtZGFzaCI+PGRpdiBj"
"bGFzcz0iZW1wdHktc3RhdGUiPjxkaXYgY2xhc3M9ImVtcHR5LWljbyI+8J+UjTwvZGl2PjxkaXYgY2xh"
"c3M9ImVtcHR5LXRpdGxlIj5ObyBQb3J0cyBGb3VuZCBZZXQ8L2Rpdj48ZGl2IGNsYXNzPSJlbXB0eS1z"
"dWIiPlJ1biBhIHBvcnQgc2NhbiB0byBwb3B1bGF0ZSB0aGlzIGRhc2hib2FyZDwvZGl2PjwvZGl2Pjwv"
"ZGl2PjwvZGl2PgoKICAgIDwhLS0gVEhSRUFUUyAtLT4KICAgIDxkaXYgY2xhc3M9InRhYi1wYW5lIiBp"
"ZD0icGFuZS10aHJlYXRzIj48ZGl2IGlkPSJ0aHJlYXQtZGFzaCI+PGRpdiBjbGFzcz0iZW1wdHktc3Rh"
"dGUiPjxkaXYgY2xhc3M9ImVtcHR5LWljbyI+8J+boTwvZGl2PjxkaXYgY2xhc3M9ImVtcHR5LXRpdGxl"
"Ij5ObyBUaHJlYXRzIERldGVjdGVkPC9kaXY+PGRpdiBjbGFzcz0iZW1wdHktc3ViIj5SdW4gdnVsbmVy"
"YWJpbGl0eSBzY2FucyB0byBkaXNjb3ZlciB0aHJlYXRzPC9kaXY+PC9kaXY+PC9kaXY+PC9kaXY+Cgog"
"ICAgPCEtLSBSSVNLIEFOQUxZU0lTIC0tPgogICAgPGRpdiBjbGFzcz0idGFiLXBhbmUiIGlkPSJwYW5l"
"LXJpc2siPjxkaXYgaWQ9InJpc2stY29udGVudCI+PGRpdiBjbGFzcz0iZW1wdHktc3RhdGUiPjxkaXYg"
"Y2xhc3M9ImVtcHR5LWljbyI+8J+TijwvZGl2PjxkaXYgY2xhc3M9ImVtcHR5LXRpdGxlIj5ObyBSaXNr"
"IERhdGE8L2Rpdj48ZGl2IGNsYXNzPSJlbXB0eS1zdWIiPlJ1biBzY2FucyB0byBnZW5lcmF0ZSByaXNr"
"IGFuYWx5c2lzPC9kaXY+PC9kaXY+PC9kaXY+PC9kaXY+CgogICAgPCEtLSBUSFJFQVQgR1JBUEggLS0+"
"CiAgICA8ZGl2IGNsYXNzPSJ0YWItcGFuZSIgaWQ9InBhbmUtdGdyYXBoIj48ZGl2IGlkPSJ0Z3JhcGgt"
"Y29udGVudCI+PGRpdiBjbGFzcz0iZW1wdHktc3RhdGUiPjxkaXYgY2xhc3M9ImVtcHR5LWljbyI+8J+V"
"uDwvZGl2PjxkaXYgY2xhc3M9ImVtcHR5LXRpdGxlIj5ObyBUaHJlYXQgRGF0YTwvZGl2PjxkaXYgY2xh"
"c3M9ImVtcHR5LXN1YiI+UnVuIHNjYW5zIHRvIGdlbmVyYXRlIHRocmVhdCBhbmFseXNpczwvZGl2Pjwv"
"ZGl2PjwvZGl2PjwvZGl2PgoKICAgIDwhLS0gU0NBTiBTVEFUVVMgLS0+CiAgICA8ZGl2IGNsYXNzPSJ0"
"YWItcGFuZSIgaWQ9InBhbmUtc2NhbnN0YXR1cyI+CiAgICAgIDxkaXYgaWQ9InNjYW4tc3RhdHVzLWNv"
"bnRlbnQiPgogICAgICAgIDwhLS0gTGl2ZSBTY2FuIENhcmQgLS0+CiAgICAgICAgPGRpdiBjbGFzcz0i"
"Y2FyZCIgaWQ9ImxpdmUtc2Nhbi1jYXJkIiBzdHlsZT0ibWFyZ2luLWJvdHRvbToyMHB4O2JvcmRlci1s"
"ZWZ0OjRweCBzb2xpZCB2YXIoLS13aGl0ZS00KSI+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJjYXJkLWhl"
"YWRlciI+CiAgICAgICAgICAgIDxkaXY+PGRpdiBjbGFzcz0iY2FyZC10aXRsZSI+Q3VycmVudCBTY2Fu"
"PC9kaXY+PGRpdiBjbGFzcz0iY2FyZC1zdWJ0aXRsZSIgaWQ9InNzLXN1YnRpdGxlIj5ObyBhY3RpdmUg"
"c2NhbjwvZGl2PjwvZGl2PgogICAgICAgICAgICA8ZGl2IGNsYXNzPSJzY2FuLWluZGljYXRvciIgaWQ9"
"InNjYW4taW5kaWNhdG9yIiBzdHlsZT0id2lkdGg6NDJweDtoZWlnaHQ6NDJweCI+PHNwYW4gY2xhc3M9"
"InNjYW4tcGN0IiBpZD0ic2Nhbi1wY3QtbnVtIiBzdHlsZT0iZm9udC1zaXplOjEycHgiPuKAlDwvc3Bh"
"bj48L2Rpdj4KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPGRpdiBzdHlsZT0iZGlzcGxheTpmbGV4"
"O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6MjBweDttYXJnaW4tYm90dG9tOjE0cHgiPgogICAgICAgICAg"
"ICA8ZGl2IHN0eWxlPSJmbGV4OjEiPgogICAgICAgICAgICAgIDxkaXYgc3R5bGU9ImRpc3BsYXk6Zmxl"
"eDthbGlnbi1pdGVtczpiYXNlbGluZTtnYXA6MTBweDttYXJnaW4tYm90dG9tOjZweCI+CiAgICAgICAg"
"ICAgICAgICA8ZGl2IGlkPSJzY2FuLXRvb2wtbmFtZSIgc3R5bGU9ImZvbnQtc2l6ZToxNnB4O2ZvbnQt"
"d2VpZ2h0OjgwMDtjb2xvcjp2YXIoLS10eC1kYXJrKTtmb250LWZhbWlseTonU3luZScsc2Fucy1zZXJp"
"ZiI+4oCUPC9kaXY+CiAgICAgICAgICAgICAgICA8ZGl2IGlkPSJzY2FuLXBoYXNlLWJhZGdlIiBzdHls"
"ZT0iZm9udC1mYW1pbHk6J0lCTSBQbGV4IE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6OXB4O2ZvbnQt"
"d2VpZ2h0OjcwMDtwYWRkaW5nOjNweCAxMHB4O2JvcmRlci1yYWRpdXM6MjBweDtiYWNrZ3JvdW5kOnZh"
"cigtLXdoaXRlLTIpO2NvbG9yOnZhcigtLXR4LW11dGVkKTtsZXR0ZXItc3BhY2luZzoxcHgiPklETEU8"
"L2Rpdj4KICAgICAgICAgICAgICA8L2Rpdj4KICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJkaXNwbGF5"
"OmZsZXg7Z2FwOjE2cHg7ZmxleC13cmFwOndyYXAiPgogICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0i"
"c2Nhbi1tZXRhLWl0ZW0iPjxkaXYgY2xhc3M9ImRvdCIgc3R5bGU9ImJhY2tncm91bmQ6dmFyKC0tcmVk"
"KSI+PC9kaXY+VGFyZ2V0OiA8c3Ryb25nIGlkPSJzY2FuLXRhcmdldCIgc3R5bGU9ImNvbG9yOnZhcigt"
"LXR4LWRhcmspIj7igJQ8L3N0cm9uZz48L2Rpdj4KICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InNj"
"YW4tbWV0YS1pdGVtIj48ZGl2IGNsYXNzPSJkb3QiIHN0eWxlPSJiYWNrZ3JvdW5kOnZhcigtLXNldi1o"
"aWdoKSI+PC9kaXY+Q2F0ZWdvcnk6IDxzdHJvbmcgaWQ9InNjYW4tY2F0IiBzdHlsZT0iY29sb3I6dmFy"
"KC0tdHgtZGFyaykiPuKAlDwvc3Ryb25nPjwvZGl2PgogICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0i"
"c2Nhbi1tZXRhLWl0ZW0iPjxkaXYgY2xhc3M9ImRvdCIgc3R5bGU9ImJhY2tncm91bmQ6dmFyKC0tc2V2"
"LWxvdykiPjwvZGl2PkVsYXBzZWQ6IDxzdHJvbmcgaWQ9InNjYW4tZWxhcHNlZCIgc3R5bGU9ImNvbG9y"
"OnZhcigtLXR4LWRhcmspIj4wLjBzPC9zdHJvbmc+PC9kaXY+CiAgICAgICAgICAgICAgPC9kaXY+CiAg"
"ICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPC9kaXY+CiAgICAgICAgICA8IS0tIFByb2dyZXNzIEJh"
"ciAtLT4KICAgICAgICAgIDxkaXYgc3R5bGU9Im1hcmdpbi1ib3R0b206OHB4Ij4KICAgICAgICAgICAg"
"PGRpdiBzdHlsZT0iZGlzcGxheTpmbGV4O2p1c3RpZnktY29udGVudDpzcGFjZS1iZXR3ZWVuO21hcmdp"
"bi1ib3R0b206NXB4Ij4KICAgICAgICAgICAgICA8ZGl2IGlkPSJzY2FuLW1lc3NhZ2UiIHN0eWxlPSJm"
"b250LXNpemU6MTFweDtjb2xvcjp2YXIoLS10eC1tdXRlZCk7Zm9udC1zdHlsZTppdGFsaWMiPlJlYWR5"
"IOKAlCBzZWxlY3QgYSB0b29sIHRvIGJlZ2luPC9kaXY+CiAgICAgICAgICAgICAgPGRpdiBpZD0ic2Nh"
"bi1wY3QtdGV4dCIgc3R5bGU9ImZvbnQtZmFtaWx5OidJQk0gUGxleCBNb25vJyxtb25vc3BhY2U7Zm9u"
"dC1zaXplOjExcHg7Zm9udC13ZWlnaHQ6NzAwO2NvbG9yOnZhcigtLXR4LWRhcmspIj4wJTwvZGl2Pgog"
"ICAgICAgICAgICA8L2Rpdj4KICAgICAgICAgICAgPGRpdiBjbGFzcz0ic2Nhbi1iYXItdHJhY2siPjxk"
"aXYgY2xhc3M9InNjYW4tYmFyLWZpbGwtbGl2ZSIgaWQ9InNjYW4tYmFyLWZpbGwiIHN0eWxlPSJ3aWR0"
"aDowJSI+PC9kaXY+PC9kaXY+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICA8L2Rpdj4KCiAgICAgICAg"
"PCEtLSBTdGF0cyBSb3cgLS0+CiAgICAgICAgPGRpdiBjbGFzcz0iZGFzaC1ncmlkIGNvbHMtNCIgc3R5"
"bGU9Im1hcmdpbi1ib3R0b206MjBweCI+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJjYXJkIj48ZGl2IGNs"
"YXNzPSJjYXJkLXN1YnRpdGxlIj5Ub3RhbCBTY2FuczwvZGl2PjxkaXYgY2xhc3M9InN0YXQtbnVtIGJy"
"YW5kIiBpZD0ic3MtdG90YWwiPjA8L2Rpdj48L2Rpdj4KICAgICAgICAgIDxkaXYgY2xhc3M9ImNhcmQi"
"PjxkaXYgY2xhc3M9ImNhcmQtc3VidGl0bGUiPlBvcnRzIEZvdW5kPC9kaXY+PGRpdiBjbGFzcz0ic3Rh"
"dC1udW0gb3JhbmdlIiBpZD0ic3MtcG9ydHMiPjA8L2Rpdj48L2Rpdj4KICAgICAgICAgIDxkaXYgY2xh"
"c3M9ImNhcmQiPjxkaXYgY2xhc3M9ImNhcmQtc3VidGl0bGUiPlRocmVhdHMgRm91bmQ8L2Rpdj48ZGl2"
"IGNsYXNzPSJzdGF0LW51bSByZWQiIGlkPSJzcy10aHJlYXRzIj4wPC9kaXY+PC9kaXY+CiAgICAgICAg"
"ICA8ZGl2IGNsYXNzPSJjYXJkIj48ZGl2IGNsYXNzPSJjYXJkLXN1YnRpdGxlIj5BdmcgRHVyYXRpb248"
"L2Rpdj48ZGl2IGNsYXNzPSJzdGF0LW51bSIgaWQ9InNzLWF2ZyIgc3R5bGU9ImNvbG9yOnZhcigtLXR4"
"LWRhcmspIj4wczwvZGl2PjwvZGl2PgogICAgICAgIDwvZGl2PgoKICAgICAgICA8IS0tIFNjYW4gSGlz"
"dG9yeSBUYWJsZSAtLT4KICAgICAgICA8ZGl2IGNsYXNzPSJjYXJkIj4KICAgICAgICAgIDxkaXYgY2xh"
"c3M9ImNhcmQtaGVhZGVyIj48ZGl2PjxkaXYgY2xhc3M9ImNhcmQtdGl0bGUiPlNjYW4gSGlzdG9yeTwv"
"ZGl2PjxkaXYgY2xhc3M9ImNhcmQtc3VidGl0bGUiPkxhc3QgMTUgY29tcGxldGVkIHNjYW5zPC9kaXY+"
"PC9kaXY+PC9kaXY+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJwb3J0LXRhYmxlLXdyYXAiPgogICAgICAg"
"ICAgICA8dGFibGUgY2xhc3M9InBvcnQtdGFibGUiPgogICAgICAgICAgICAgIDx0aGVhZD48dHI+PHRo"
"PlN0YXR1czwvdGg+PHRoPlRvb2w8L3RoPjx0aD5UYXJnZXQ8L3RoPjx0aD5EdXJhdGlvbjwvdGg+PHRo"
"PlBvcnRzPC90aD48dGg+VGhyZWF0czwvdGg+PHRoPlRpbWU8L3RoPjwvdHI+PC90aGVhZD4KICAgICAg"
"ICAgICAgICA8dGJvZHkgaWQ9InNzLWhpc3RvcnktdGFibGUiPgogICAgICAgICAgICAgICAgPHRyPjx0"
"ZCBjb2xzcGFuPSI3IiBzdHlsZT0idGV4dC1hbGlnbjpjZW50ZXI7Y29sb3I6dmFyKC0tdHgtZmFpbnQp"
"O3BhZGRpbmc6MzBweCI+Tm8gc2NhbnMgY29tcGxldGVkIHlldDwvdGQ+PC90cj4KICAgICAgICAgICAg"
"ICA8L3Rib2R5PgogICAgICAgICAgICA8L3RhYmxlPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgPC9k"
"aXY+CiAgICAgIDwvZGl2PgogICAgPC9kaXY+CiAgPC9kaXY+CgogIDxkaXYgY2xhc3M9ImNoYXQtcGFu"
"ZWwgY29sbGFwc2VkIiBpZD0iY2hhdC1wYW5lbCI+CiAgICA8ZGl2IGNsYXNzPSJjaGF0LXRvZ2dsZSIg"
"b25jbGljaz0idG9nZ2xlQ2hhdCgpIj4KICAgICAgPGRpdiBjbGFzcz0iY2hhdC10b2dnbGUtbGVmdCI+"
"PHNwYW4gc3R5bGU9ImNvbG9yOnZhcigtLXJlZCkiPuKXjzwvc3Bhbj48c3BhbiBjbGFzcz0iY2hhdC10"
"b2dnbGUtbGFiZWwiPkhBUlNIQSBBSSBBU1NJU1RBTlQ8L3NwYW4+PHNwYW4gY2xhc3M9ImNoYXQtdG9n"
"Z2xlLXN0YXR1cyI+4pePIE9ubGluZTwvc3Bhbj48L2Rpdj4KICAgICAgPHNwYW4gY2xhc3M9ImNoYXQt"
"YXJyb3ciPuKWvDwvc3Bhbj4KICAgIDwvZGl2PgogICAgPGRpdiBpZD0iY2hhdC1tZXNzYWdlcyI+PGRp"
"diBjbGFzcz0ibXNnIGFpIj48ZGl2IGNsYXNzPSJtc2ctYXZhdGFyIj5BSTwvZGl2PjxkaXYgY2xhc3M9"
"Im1zZy1ib2R5Ij5IQVJTSEEgQUkgdjcuMCBvbmxpbmUuIFNlbGVjdCBhIHRvb2wgYW5kIGVudGVyIGEg"
"dGFyZ2V0IHRvIGJlZ2luLjwvZGl2PjwvZGl2PjwvZGl2PgogICAgPGRpdiBjbGFzcz0iY2hhdC1pbnB1"
"dC1yb3ciPgogICAgICA8aW5wdXQgdHlwZT0idGV4dCIgaWQ9ImNoYXQtaW5wdXQiIGNsYXNzPSJjaGF0"
"LWlucHV0IiBwbGFjZWhvbGRlcj0iQXNrIEhBUlNIQSBBSS4uLiIgb25rZXlkb3duPSJpZihldmVudC5r"
"ZXk9PT0nRW50ZXInKXNlbmRDaGF0KCkiPgogICAgICA8YnV0dG9uIGNsYXNzPSJjaGF0LXNlbmQiIG9u"
"Y2xpY2s9InNlbmRDaGF0KCkiPlNFTkQ8L2J1dHRvbj4KICAgIDwvZGl2PgogIDwvZGl2Pgo8L2Rpdj4K"
"PC9kaXY+Cgo8IS0tIFJFUE9SVCBNT0RBTCAtLT4KPGRpdiBjbGFzcz0ibW9kYWwtb3ZlcmxheSIgaWQ9"
"InJlcG9ydC1tb2RhbCI+CiAgPGRpdiBjbGFzcz0ibW9kYWwtYm94Ij4KICAgIDxkaXYgY2xhc3M9Im1v"
"ZGFsLWhkciI+PGRpdiBjbGFzcz0ibW9kYWwtdGl0bGUiPkhBUlNIQSB2Ny4wIOKAlCBWQVBUIFJFUE9S"
"VDwvZGl2PjxidXR0b24gY2xhc3M9Im1vZGFsLWNsb3NlIiBvbmNsaWNrPSJjbG9zZVJlcG9ydCgpIj5D"
"TE9TRTwvYnV0dG9uPjwvZGl2PgogICAgPGRpdiBjbGFzcz0ibW9kYWwtYm9keSI+PGRpdiBpZD0icnAi"
"PjwvZGl2PjwvZGl2PgogICAgPGRpdiBjbGFzcz0ibW9kYWwtZm9vdGVyIj48YnV0dG9uIGNsYXNzPSJk"
"bC1idG4gcHJpbWFyeSIgb25jbGljaz0iZG93bmxvYWRIVE1MKCkiPkRvd25sb2FkIEhUTUw8L2J1dHRv"
"bj48YnV0dG9uIGNsYXNzPSJkbC1idG4gc2Vjb25kYXJ5IiBvbmNsaWNrPSJkb3dubG9hZFRYVCgpIj5E"
"b3dubG9hZCBUWFQ8L2J1dHRvbj48L2Rpdj4KICA8L2Rpdj4KPC9kaXY+Cgo8c2NyaXB0PgovKiA9PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"CiAgIFNUQVRFCiAgID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT0gKi8KdmFyIHNjYW5Db3VudD0wLGN1cnJlbnRBdWRpbz1udWxsLGFsbFBv"
"cnRzPVtdLGFsbFRocmVhdHM9W10sbGFzdFRhcmdldD0nJzsKdmFyIFNDPXtuZXQ6MCx3ZWI6MCxpbmY6"
"MCxyZWM6MH07CnZhciByaXNrQ2hhcnRzPXt9LHRocmVhdENoYXJ0cz17fTsKdmFyIHNldkNvbG9ycz17"
"Q1JJVElDQUw6JyNkOTA0MjknLEhJR0g6JyNlODVkMDQnLE1FRElVTTonI2UwOWYzZScsTE9XOicjMmQ2"
"YTRmJ307CnZhciBzZXZCZz17Q1JJVElDQUw6J3JnYmEoMjE3LDQsNDEsMC4xKScsSElHSDoncmdiYSgy"
"MzIsOTMsNCwwLjEpJyxNRURJVU06J3JnYmEoMjI0LDE1OSw2MiwwLjEpJyxMT1c6J3JnYmEoNDUsMTA2"
"LDc5LDAuMSknfTsKdmFyIHRhcmdldEhpc3Rvcnk9W107CnZhciBsYXN0UGhhc2U9J2lkbGUnOwoKLyog"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PQogICBDTE9DSwogICA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09ICovCmZ1bmN0aW9uIHVwZGF0ZUNsb2NrKCl7ZG9jdW1lbnQuZ2V0"
"RWxlbWVudEJ5SWQoJ2Nsb2NrJykudGV4dENvbnRlbnQ9bmV3IERhdGUoKS50b0xvY2FsZVRpbWVTdHJp"
"bmcoJ2VuLVVTJyx7aG91cjonMi1kaWdpdCcsbWludXRlOicyLWRpZ2l0JyxzZWNvbmQ6JzItZGlnaXQn"
"fSl9CnNldEludGVydmFsKHVwZGF0ZUNsb2NrLDEwMDApO3VwZGF0ZUNsb2NrKCk7CgovKiA9PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiAg"
"IFRBQlMKICAgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PSAqLwpmdW5jdGlvbiBzd2l0Y2hUYWIodGFiLGJ0bil7CiAgZG9jdW1lbnQucXVl"
"cnlTZWxlY3RvckFsbCgnLnRhYi1wYW5lJykuZm9yRWFjaChmdW5jdGlvbihwKXtwLmNsYXNzTGlzdC5y"
"ZW1vdmUoJ2FjdGl2ZScpfSk7CiAgZG9jdW1lbnQucXVlcnlTZWxlY3RvckFsbCgnLnRhYi1idG4nKS5m"
"b3JFYWNoKGZ1bmN0aW9uKGIpe2IuY2xhc3NMaXN0LnJlbW92ZSgnYWN0aXZlJyl9KTsKICBkb2N1bWVu"
"dC5nZXRFbGVtZW50QnlJZCgncGFuZS0nK3RhYikuY2xhc3NMaXN0LmFkZCgnYWN0aXZlJyk7CiAgaWYo"
"YnRuKWJ0bi5jbGFzc0xpc3QuYWRkKCdhY3RpdmUnKTsKICBpZih0YWI9PT0ncmlzaycpc2V0VGltZW91"
"dChyZWZyZXNoUmlza0NoYXJ0cyw2MCk7CiAgaWYodGFiPT09J3RncmFwaCcpc2V0VGltZW91dChyZWZy"
"ZXNoVGhyZWF0Q2hhcnRzLDYwKTsKfQpmdW5jdGlvbiB0b2dnbGVDaGF0KCl7ZG9jdW1lbnQuZ2V0RWxl"
"bWVudEJ5SWQoJ2NoYXQtcGFuZWwnKS5jbGFzc0xpc3QudG9nZ2xlKCdjb2xsYXBzZWQnKX0KCi8qID09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT0KICAgU0lERUJBUiBEUk9QRE9XTlMKICAgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PSAqLwpmdW5jdGlvbiB0b2dnbGVTZWN0aW9uKGhl"
"YWRlcil7CiAgaGVhZGVyLnBhcmVudEVsZW1lbnQuY2xhc3NMaXN0LnRvZ2dsZSgnb3BlbicpOwp9Cgov"
"KiA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09CiAgIFRPT0wgU0VBUkNIIC8gRklMVEVSCiAgID09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0gKi8KZnVuY3Rpb24gZmlsdGVyVG9v"
"bHMocXVlcnkpewogIHZhciBxPXF1ZXJ5LnRvTG93ZXJDYXNlKCkudHJpbSgpOwogIHZhciBuYXZzPWRv"
"Y3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJy5zLW5hdicpOwogIHZhciBzZWN0aW9ucz1kb2N1bWVudC5x"
"dWVyeVNlbGVjdG9yQWxsKCcucy1zZWN0aW9uJyk7CiAgaWYoIXEpewogICAgbmF2cy5mb3JFYWNoKGZ1"
"bmN0aW9uKG4pe24uc3R5bGUuZGlzcGxheT0nJ30pOwogICAgc2VjdGlvbnMuZm9yRWFjaChmdW5jdGlv"
"bihzKXsKICAgICAgdmFyIGhkcj1zLnF1ZXJ5U2VsZWN0b3IoJy5zLXNlY3Rpb24taGVhZGVyJyk7CiAg"
"ICAgIGlmKGhkciloZHIuc3R5bGUuZGlzcGxheT0nJzsKICAgIH0pOwogICAgcmV0dXJuOwogIH0KICBz"
"ZWN0aW9ucy5mb3JFYWNoKGZ1bmN0aW9uKHMpe3MuY2xhc3NMaXN0LmFkZCgnb3BlbicpfSk7CiAgbmF2"
"cy5mb3JFYWNoKGZ1bmN0aW9uKG4pewogICAgdmFyIG5hbWU9KG4uZ2V0QXR0cmlidXRlKCdkYXRhLW5h"
"bWUnKXx8JycpKycgJysobi50ZXh0Q29udGVudHx8JycpOwogICAgbi5zdHlsZS5kaXNwbGF5PW5hbWUu"
"dG9Mb3dlckNhc2UoKS5pbmRleE9mKHEpPj0wPycnOidub25lJzsKICB9KTsKICBzZWN0aW9ucy5mb3JF"
"YWNoKGZ1bmN0aW9uKHMpewogICAgdmFyIGJvZHk9cy5xdWVyeVNlbGVjdG9yKCcucy1zZWN0aW9uLWJv"
"ZHknKTsKICAgIGlmKCFib2R5KXJldHVybjsKICAgIHZhciB2aXNpYmxlPWJvZHkucXVlcnlTZWxlY3Rv"
"ckFsbCgnLnMtbmF2Om5vdChbc3R5bGUqPSJkaXNwbGF5OiBub25lIl0pJyk7CiAgICB2YXIgaGRyPXMu"
"cXVlcnlTZWxlY3RvcignLnMtc2VjdGlvbi1oZWFkZXInKTsKICAgIGlmKGhkciloZHIuc3R5bGUuZGlz"
"cGxheT12aXNpYmxlLmxlbmd0aD4wPycnOidub25lJzsKICB9KTsKfQoKLyogPT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQogICBUQVJHRVQg"
"SElTVE9SWQogICA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09ICovCmZ1bmN0aW9uIGFkZFRhcmdldEhpc3RvcnkodCl7CiAgaWYoIXR8fHRh"
"cmdldEhpc3RvcnkuaW5kZXhPZih0KT49MClyZXR1cm47CiAgdGFyZ2V0SGlzdG9yeS51bnNoaWZ0KHQp"
"OwogIGlmKHRhcmdldEhpc3RvcnkubGVuZ3RoPjEwKXRhcmdldEhpc3RvcnkucG9wKCk7Cn0KZnVuY3Rp"
"b24gc2hvd1RhcmdldEhpc3RvcnkoKXsKICB2YXIgYm94PWRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0"
"YXJnZXQtaGlzdG9yeScpOwogIHZhciBpbnA9ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RhcmdldC1p"
"bnB1dCcpLnZhbHVlLnRyaW0oKS50b0xvd2VyQ2FzZSgpOwogIGlmKCF0YXJnZXRIaXN0b3J5Lmxlbmd0"
"aCl7Ym94LmNsYXNzTGlzdC5yZW1vdmUoJ3Nob3cnKTtyZXR1cm59CiAgdmFyIGZpbHRlcmVkPXRhcmdl"
"dEhpc3RvcnkuZmlsdGVyKGZ1bmN0aW9uKHQpe3JldHVybiAhaW5wfHx0LnRvTG93ZXJDYXNlKCkuaW5k"
"ZXhPZihpbnApPj0wfSk7CiAgaWYoIWZpbHRlcmVkLmxlbmd0aCl7Ym94LmNsYXNzTGlzdC5yZW1vdmUo"
"J3Nob3cnKTtyZXR1cm59CiAgdmFyIGg9JzxkaXYgY2xhc3M9ImgtdGgtbGFiZWwiIHN0eWxlPSJwYWRk"
"aW5nOjZweCAxNHB4IDJweCI+UkVDRU5UIFRBUkdFVFM8L2Rpdj4nOwogIGZpbHRlcmVkLmZvckVhY2go"
"ZnVuY3Rpb24odCl7CiAgICBoKz0nPGRpdiBjbGFzcz0iaC10aC1pdGVtIiBvbmNsaWNrPSJzZWxlY3RU"
"YXJnZXQoJnF1b3Q7Jyt0LnJlcGxhY2UoLyIvZywnJykrJyZxdW90OykiPicrdCsnPC9kaXY+JzsKICB9"
"KTsKICBib3guaW5uZXJIVE1MPWg7Ym94LmNsYXNzTGlzdC5hZGQoJ3Nob3cnKTsKfQpmdW5jdGlvbiBz"
"ZWxlY3RUYXJnZXQodCl7CiAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RhcmdldC1pbnB1dCcpLnZh"
"bHVlPXQ7CiAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RhcmdldC1oaXN0b3J5JykuY2xhc3NMaXN0"
"LnJlbW92ZSgnc2hvdycpOwp9CmRvY3VtZW50LmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJyxmdW5jdGlv"
"bihlKXsKICBpZighZS50YXJnZXQuY2xvc2VzdCgnLmgtdGFyZ2V0Jykpe3ZhciBlbD1kb2N1bWVudC5n"
"ZXRFbGVtZW50QnlJZCgndGFyZ2V0LWhpc3RvcnknKTtpZihlbCllbC5jbGFzc0xpc3QucmVtb3ZlKCdz"
"aG93Jyl9Cn0pOwoKLyogPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PQogICBVVElMUwogICA9PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovCmZ1bmN0aW9uIHBsYXlWb2ljZSgp"
"e2lmKGN1cnJlbnRBdWRpbyljdXJyZW50QXVkaW8ucGF1c2UoKTtjdXJyZW50QXVkaW89bmV3IEF1ZGlv"
"KCcvdm9pY2U/dD0nK0RhdGUubm93KCkpO2N1cnJlbnRBdWRpby5wbGF5KCkuY2F0Y2goZnVuY3Rpb24o"
"KXt9KX0KZnVuY3Rpb24gbm90aWZ5KG1zZyl7dmFyIGVsPWRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2Rp"
"dicpO2VsLmNsYXNzTmFtZT0nbm90aWYnO2VsLnRleHRDb250ZW50PW1zZztkb2N1bWVudC5ib2R5LmFw"
"cGVuZENoaWxkKGVsKTtzZXRUaW1lb3V0KGZ1bmN0aW9uKCl7ZWwucmVtb3ZlKCl9LDM1MDApfQoKdmFy"
"IHRlcm1pbmFsPWRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0ZXJtaW5hbC1vdXRwdXQnKTsKZnVuY3Rp"
"b24gdGVybUxpbmUodCxjKXtpZighYyljPSdyZXN1bHQnOyh0KycnKS5zcGxpdCgnXG4nKS5mb3JFYWNo"
"KGZ1bmN0aW9uKGwpe2lmKCFsLnRyaW0oKSlyZXR1cm47dmFyIGQ9ZG9jdW1lbnQuY3JlYXRlRWxlbWVu"
"dCgnZGl2Jyk7ZC5jbGFzc05hbWU9J3RsICcrYztkLnRleHRDb250ZW50PWw7dGVybWluYWwuYXBwZW5k"
"Q2hpbGQoZCl9KTt0ZXJtaW5hbC5zY3JvbGxUb3A9dGVybWluYWwuc2Nyb2xsSGVpZ2h0fQpmdW5jdGlv"
"biBjbGVhclRlcm1pbmFsKCl7dGVybWluYWwuaW5uZXJIVE1MPSc8ZGl2IGNsYXNzPSJ0bCBoZHIiPi8v"
"IENMRUFSRUQg4oCUIEhBUlNIQSBBSSB2Ny4wPC9kaXY+J30KZnVuY3Rpb24gY29weU91dHB1dCgpe25h"
"dmlnYXRvci5jbGlwYm9hcmQud3JpdGVUZXh0KHRlcm1pbmFsLmlubmVyVGV4dCkudGhlbihmdW5jdGlv"
"bigpe25vdGlmeSgnQ29waWVkIScpfSl9CmZ1bmN0aW9uIHNldExvYWRpbmcob24pe2RvY3VtZW50Lmdl"
"dEVsZW1lbnRCeUlkKCdsb2FkaW5nLWJhcicpLnN0eWxlLmRpc3BsYXk9b24/J2Jsb2NrJzonbm9uZSd9"
"CgpmdW5jdGlvbiB1cGRhdGVTdGF0cygpewogIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzdGF0LXNj"
"YW5zJykudGV4dENvbnRlbnQ9c2NhbkNvdW50OwogIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzdGF0"
"LXBvcnRzJykudGV4dENvbnRlbnQ9YWxsUG9ydHMubGVuZ3RoOwogIGRvY3VtZW50LmdldEVsZW1lbnRC"
"eUlkKCdzdGF0LXRocmVhdHMnKS50ZXh0Q29udGVudD1hbGxUaHJlYXRzLmxlbmd0aDsKICBkb2N1bWVu"
"dC5nZXRFbGVtZW50QnlJZCgnc2Nhbi1iYXInKS5zdHlsZS53aWR0aD1NYXRoLm1pbigxMDAsc2NhbkNv"
"dW50KjEwKSsnJSc7CiAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3BvcnQtYmFyJykuc3R5bGUud2lk"
"dGg9TWF0aC5taW4oMTAwLGFsbFBvcnRzLmxlbmd0aCo1KSsnJSc7CiAgZG9jdW1lbnQuZ2V0RWxlbWVu"
"dEJ5SWQoJ3RocmVhdC1iYXInKS5zdHlsZS53aWR0aD1NYXRoLm1pbigxMDAsYWxsVGhyZWF0cy5sZW5n"
"dGgqMTApKyclJzsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnaG0tc2NhbnMnKS50ZXh0Q29udGVu"
"dD1zY2FuQ291bnQ7CiAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2htLXBvcnRzJykudGV4dENvbnRl"
"bnQ9YWxsUG9ydHMubGVuZ3RoOwogIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdobS10aHJlYXRzJyku"
"dGV4dENvbnRlbnQ9YWxsVGhyZWF0cy5sZW5ndGg7Cn0KCi8qID09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAgUE9SVCBEQVNIQk9BUkQK"
"ICAgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PSAqLwpmdW5jdGlvbiB1cGRhdGVQb3J0RGFzaChwb3J0cyx0YXJnZXQpewogIGlmKCFwb3J0"
"c3x8IXBvcnRzLmxlbmd0aClyZXR1cm47CiAgcG9ydHMuZm9yRWFjaChmdW5jdGlvbihwKXtpZighYWxs"
"UG9ydHMuZmluZChmdW5jdGlvbih4KXtyZXR1cm4geC5wb3J0PT09cC5wb3J0JiZ4LnByb3RvPT09cC5w"
"cm90b30pKWFsbFBvcnRzLnB1c2gocCl9KTsKICB2YXIgdG90YWw9YWxsUG9ydHMubGVuZ3RoLGNyaXQ9"
"MCxoaWdoPTAsbWVkPTAsbG93PTA7CiAgYWxsUG9ydHMuZm9yRWFjaChmdW5jdGlvbihwKXtpZihwLnNl"
"dmVyaXR5PT09J0NSSVRJQ0FMJyljcml0Kys7ZWxzZSBpZihwLnNldmVyaXR5PT09J0hJR0gnKWhpZ2gr"
"KztlbHNlIGlmKHAuc2V2ZXJpdHk9PT0nTUVESVVNJyltZWQrKztlbHNlIGxvdysrfSk7CiAgdmFyIGJh"
"ZGdlPWRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdwb3J0LWJhZGdlJyk7YmFkZ2UuY2xhc3NMaXN0LmFk"
"ZCgnc2hvdycsJ2Itb3JhbmdlJyk7YmFkZ2UudGV4dENvbnRlbnQ9dG90YWw7CiAgdmFyIHNvcnRlZD1h"
"bGxQb3J0cy5zbGljZSgpLnNvcnQoZnVuY3Rpb24oYSxiKXt2YXIgbz17Q1JJVElDQUw6MCxISUdIOjEs"
"TUVESVVNOjIsTE9XOjN9O3JldHVybihvW2Euc2V2ZXJpdHldfHwzKS0ob1tiLnNldmVyaXR5XXx8Myl8"
"fGEucG9ydC1iLnBvcnR9KTsKICB2YXIgaD0nPGRpdiBjbGFzcz0iZGFzaC1ncmlkIGNvbHMtNCIgc3R5"
"bGU9Im1hcmdpbi1ib3R0b206MjBweCI+JzsKICBoKz0nPGRpdiBjbGFzcz0iY2FyZCI+PGRpdiBjbGFz"
"cz0iY2FyZC1zdWJ0aXRsZSI+Q3JpdGljYWw8L2Rpdj48ZGl2IGNsYXNzPSJzdGF0LW51bSByZWQiPicr"
"Y3JpdCsnPC9kaXY+PGRpdiBjbGFzcz0ic3RhdC1iYXItd3JhcCI+PGRpdiBjbGFzcz0ic3RhdC1iYXIi"
"PjxkaXYgY2xhc3M9InN0YXQtYmFyLWZpbGwgcmVkIiBzdHlsZT0id2lkdGg6JytNYXRoLm1pbigxMDAs"
"Y3JpdCoyNSkrJyUiPjwvZGl2PjwvZGl2PjwvZGl2PjwvZGl2Pic7CiAgaCs9JzxkaXYgY2xhc3M9ImNh"
"cmQiPjxkaXYgY2xhc3M9ImNhcmQtc3VidGl0bGUiPkhpZ2g8L2Rpdj48ZGl2IGNsYXNzPSJzdGF0LW51"
"bSBvcmFuZ2UiPicraGlnaCsnPC9kaXY+PGRpdiBjbGFzcz0ic3RhdC1iYXItd3JhcCI+PGRpdiBjbGFz"
"cz0ic3RhdC1iYXIiPjxkaXYgY2xhc3M9InN0YXQtYmFyLWZpbGwgb3JhbmdlIiBzdHlsZT0id2lkdGg6"
"JytNYXRoLm1pbigxMDAsaGlnaCoxOCkrJyUiPjwvZGl2PjwvZGl2PjwvZGl2PjwvZGl2Pic7CiAgaCs9"
"JzxkaXYgY2xhc3M9ImNhcmQiPjxkaXYgY2xhc3M9ImNhcmQtc3VidGl0bGUiPk1lZGl1bTwvZGl2Pjxk"
"aXYgY2xhc3M9InN0YXQtbnVtIHllbGxvdyI+JyttZWQrJzwvZGl2PjxkaXYgY2xhc3M9InN0YXQtYmFy"
"LXdyYXAiPjxkaXYgY2xhc3M9InN0YXQtYmFyIj48ZGl2IGNsYXNzPSJzdGF0LWJhci1maWxsIHllbGxv"
"dyIgc3R5bGU9IndpZHRoOicrTWF0aC5taW4oMTAwLG1lZCoxOCkrJyUiPjwvZGl2PjwvZGl2PjwvZGl2"
"PjwvZGl2Pic7CiAgaCs9JzxkaXYgY2xhc3M9ImNhcmQiPjxkaXYgY2xhc3M9ImNhcmQtc3VidGl0bGUi"
"PkxvdzwvZGl2PjxkaXYgY2xhc3M9InN0YXQtbnVtIGdyZWVuIj4nK2xvdysnPC9kaXY+PGRpdiBjbGFz"
"cz0ic3RhdC1iYXItd3JhcCI+PGRpdiBjbGFzcz0ic3RhdC1iYXIiPjxkaXYgY2xhc3M9InN0YXQtYmFy"
"LWZpbGwgZ3JlZW4iIHN0eWxlPSJ3aWR0aDonK01hdGgubWluKDEwMCxsb3cqMTgpKyclIj48L2Rpdj48"
"L2Rpdj48L2Rpdj48L2Rpdj4nOwogIGgrPSc8L2Rpdj4nOwogIGgrPSc8ZGl2IGNsYXNzPSJjYXJkIj48"
"ZGl2IGNsYXNzPSJjYXJkLWhlYWRlciI+PGRpdj48ZGl2IGNsYXNzPSJjYXJkLXRpdGxlIj5PcGVuIFBv"
"cnRzIOKAlCAnKyh0YXJnZXR8fGxhc3RUYXJnZXR8fCc/JykrJzwvZGl2PjxkaXYgY2xhc3M9ImNhcmQt"
"c3VidGl0bGUiPicrdG90YWwrJyBwb3J0czwvZGl2PjwvZGl2PjwvZGl2Pic7CiAgaCs9JzxkaXYgY2xh"
"c3M9InBvcnQtdGFibGUtd3JhcCI+PHRhYmxlIGNsYXNzPSJwb3J0LXRhYmxlIj48dGhlYWQ+PHRyPjx0"
"aD5Qb3J0PC90aD48dGg+U2VydmljZTwvdGg+PHRoPlJpc2s8L3RoPjx0aD5EZXNjcmlwdGlvbjwvdGg+"
"PHRoPlJlbWVkaWF0aW9uPC90aD48L3RyPjwvdGhlYWQ+PHRib2R5Pic7CiAgc29ydGVkLmZvckVhY2go"
"ZnVuY3Rpb24ocCl7CiAgICBoKz0nPHRyPjx0ZD48c3BhbiBjbGFzcz0icC1udW0iPicrcC5wb3J0Kyc8"
"L3NwYW4+PGRpdiBjbGFzcz0icC1wcm90byI+JytwLnByb3RvLnRvVXBwZXJDYXNlKCkrJzwvZGl2Pjwv"
"dGQ+JzsKICAgIGgrPSc8dGQ+PHNwYW4gY2xhc3M9InAtc3ZjIj4nK3Auc2VydmljZSsnPC9zcGFuPicr"
"KHAudmVyc2lvbj8nPGRpdiBjbGFzcz0icC12ZXIiPicrcC52ZXJzaW9uLnN1YnN0cmluZygwLDM1KSsn"
"PC9kaXY+JzonJykrJzwvdGQ+JzsKICAgIGgrPSc8dGQ+PHNwYW4gY2xhc3M9InNldiAnK3Auc2V2ZXJp"
"dHkrJyI+JytwLnNldmVyaXR5Kyc8L3NwYW4+PC90ZD4nOwogICAgaCs9Jzx0ZCBjbGFzcz0icC1kZXNj"
"Ij4nK3AuZGVzYysnPC90ZD48dGQgY2xhc3M9InAtZml4Ij4nK3AuZml4Kyc8L3RkPjwvdHI+JzsKICB9"
"KTsKICBoKz0nPC90Ym9keT48L3RhYmxlPjwvZGl2PjwvZGl2Pic7CiAgZG9jdW1lbnQuZ2V0RWxlbWVu"
"dEJ5SWQoJ3BvcnQtZGFzaCcpLmlubmVySFRNTD1oO3VwZGF0ZVN0YXRzKCk7Cn0KCi8qID09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAg"
"VEhSRUFUIERBU0hCT0FSRAogICA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09ICovCmZ1bmN0aW9uIHVwZGF0ZVRocmVhdERhc2godGhyZWF0"
"cyl7CiAgaWYoIXRocmVhdHN8fCF0aHJlYXRzLmxlbmd0aClyZXR1cm47CiAgdGhyZWF0cy5mb3JFYWNo"
"KGZ1bmN0aW9uKHQpe2lmKCFhbGxUaHJlYXRzLmZpbmQoZnVuY3Rpb24oeCl7cmV0dXJuIHgubmFtZT09"
"PXQubmFtZX0pKWFsbFRocmVhdHMucHVzaCh0KX0pOwogIHZhciBiYWRnZT1kb2N1bWVudC5nZXRFbGVt"
"ZW50QnlJZCgndGhyZWF0LWJhZGdlJyk7YmFkZ2UuY2xhc3NMaXN0LmFkZCgnc2hvdycsJ2ItcmVkJyk7"
"YmFkZ2UudGV4dENvbnRlbnQ9YWxsVGhyZWF0cy5sZW5ndGg7CiAgdmFyIGg9JzxkaXYgY2xhc3M9ImRh"
"c2gtZ3JpZCBjb2xzLTEiIHN0eWxlPSJnYXA6MTRweCI+JzsKICBhbGxUaHJlYXRzLmZvckVhY2goZnVu"
"Y3Rpb24odCxpKXsKICAgIGgrPSc8ZGl2IGNsYXNzPSJ0aHJlYXQtY2FyZCAnK3Quc2V2ZXJpdHkrJyIg"
"c3R5bGU9ImFuaW1hdGlvbi1kZWxheTonKyhpKjAuMDUpKydzIj48ZGl2IGNsYXNzPSJ0Yy1oZHIiPjxk"
"aXYgY2xhc3M9InRjLW5hbWUiPicrdC5uYW1lKyc8L2Rpdj48c3BhbiBjbGFzcz0ic2V2ICcrdC5zZXZl"
"cml0eSsnIj4nK3Quc2V2ZXJpdHkrJzwvc3Bhbj48L2Rpdj4nOwogICAgaCs9JzxkaXYgY2xhc3M9InRj"
"LWRlc2MiPicrdC5kZXNjKyc8L2Rpdj4nOwogICAgaCs9JzxkaXYgY2xhc3M9InRjLWZpeCI+PGRpdiBj"
"bGFzcz0idGMtZml4LWxhYmVsIj5SRU1FRElBVElPTjwvZGl2PjxkaXYgY2xhc3M9InRjLWZpeC10ZXh0"
"Ij4nK3QuZml4Kyc8L2Rpdj48L2Rpdj48L2Rpdj4nOwogIH0pOwogIGgrPSc8L2Rpdj4nOwogIGRvY3Vt"
"ZW50LmdldEVsZW1lbnRCeUlkKCd0aHJlYXQtZGFzaCcpLmlubmVySFRNTD1oO3VwZGF0ZVN0YXRzKCk7"
"Cn0KCi8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT0KICAgUlVOIFRPT0wgKGludGVncmF0ZWQgd2l0aCB0YXJnZXQgaGlzdG9yeSkKICAg"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PSAqLwpmdW5jdGlvbiBydW5Ub29sKHRvb2wsYnRuLGNhdCl7CiAgdmFyIHRhcmdldD1kb2N1bWVu"
"dC5nZXRFbGVtZW50QnlJZCgndGFyZ2V0LWlucHV0JykudmFsdWUudHJpbSgpOwogIHZhciBub1Q9Wydu"
"ZXR3b3JrX3NjYW4nLCdteV9pcCcsJ3N5c3RlbV9pbmZvJywnd2VhdGhlcicsJ2FycF9zY2FuJ107CiAg"
"dmFyIG5lZWQ9dHJ1ZTtmb3IodmFyIGk9MDtpPG5vVC5sZW5ndGg7aSsrKXtpZihub1RbaV09PT10b29s"
"KXtuZWVkPWZhbHNlO2JyZWFrfX0KICBpZihuZWVkJiYhdGFyZ2V0KXtub3RpZnkoJ0VudGVyIGEgdGFy"
"Z2V0IGZpcnN0LicpO3Rlcm1MaW5lKCdQbGVhc2UgZW50ZXIgYSB0YXJnZXQuJywnZXJyb3InKTtyZXR1"
"cm59CiAgaWYodGFyZ2V0KXtsYXN0VGFyZ2V0PXRhcmdldDthZGRUYXJnZXRIaXN0b3J5KHRhcmdldCl9"
"CiAgZG9jdW1lbnQucXVlcnlTZWxlY3RvckFsbCgnLnMtbmF2JykuZm9yRWFjaChmdW5jdGlvbihiKXti"
"LmNsYXNzTGlzdC5yZW1vdmUoJ2FjdGl2ZScpfSk7CiAgaWYoYnRuKWJ0bi5jbGFzc0xpc3QuYWRkKCdh"
"Y3RpdmUnKTsKICBzZXRMb2FkaW5nKHRydWUpOwogIHN3aXRjaFRhYigndGVybWluYWwnLGRvY3VtZW50"
"LnF1ZXJ5U2VsZWN0b3JBbGwoJy50YWItYnRuJylbMF0pOwogIHRlcm1MaW5lKCcnLCdoZHInKTsKICB0"
"ZXJtTGluZSgn4oCUIFsnK2NhdC50b1VwcGVyQ2FzZSgpKyddICcrdG9vbC50b1VwcGVyQ2FzZSgpKyh0"
"YXJnZXQ/JyDihpIgJyt0YXJnZXQ6JycpKycg4oCUJywnaGRyJyk7CiAgdGVybUxpbmUoJ2hhcnNoYUBr"
"YWxpOn4kICcrdG9vbCsodGFyZ2V0PycgJyt0YXJnZXQ6JycpKycuLi4nLCdwcm9tcHQnKTsKICB2YXIg"
"dDA9RGF0ZS5ub3coKTsKICBmZXRjaCgnL3NjYW4nLHttZXRob2Q6J1BPU1QnLGhlYWRlcnM6eydDb250"
"ZW50LVR5cGUnOidhcHBsaWNhdGlvbi9qc29uJ30sYm9keTpKU09OLnN0cmluZ2lmeSh7dG9vbDp0b29s"
"LHRhcmdldDp0YXJnZXR9KX0pCiAgLnRoZW4oZnVuY3Rpb24ocil7cmV0dXJuIHIuanNvbigpfSkKICAu"
"dGhlbihmdW5jdGlvbihkYXRhKXsKICAgIHZhciBlbD0oKERhdGUubm93KCktdDApLzEwMDApLnRvRml4"
"ZWQoMSk7CiAgICB0ZXJtTGluZShkYXRhLm91dHB1dHx8ZGF0YS5lcnJvcnx8J05vIG91dHB1dC4nLGRh"
"dGEuZXJyb3I/J2Vycm9yJzoncmVzdWx0Jyk7CiAgICB0ZXJtTGluZSgnQ29tcGxldGVkIGluICcrZWwr"
"J3Mg4oCUICcrKGRhdGEudGltZXN0YW1wfHwnJyksJ2luZm8nKTsKICAgIHNjYW5Db3VudCsrO1NDW2Nh"
"dF09KFNDW2NhdF18fDApKzE7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc3RhdC1sYXN0LXRv"
"b2wnKS50ZXh0Q29udGVudD10b29sLnRvVXBwZXJDYXNlKCk7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50"
"QnlJZCgnc3RhdC1sYXN0LXRpbWUnKS50ZXh0Q29udGVudD1lbCsncyDCtyAnK25ldyBEYXRlKCkudG9M"
"b2NhbGVUaW1lU3RyaW5nKCk7CiAgICB1cGRhdGVTdGF0cygpOwogICAgaWYoZGF0YS5wb3J0cyYmZGF0"
"YS5wb3J0cy5sZW5ndGgpe3VwZGF0ZVBvcnREYXNoKGRhdGEucG9ydHMsdGFyZ2V0KTt0ZXJtTGluZShk"
"YXRhLnBvcnRzLmxlbmd0aCsnIHBvcnRzIOKAlCBjaGVjayBQb3J0cyB0YWInLCdpbmZvJyk7bm90aWZ5"
"KGRhdGEucG9ydHMubGVuZ3RoKycgcG9ydHMgZm91bmQhJyl9CiAgICBpZihkYXRhLnRocmVhdHMmJmRh"
"dGEudGhyZWF0cy5sZW5ndGgpe3VwZGF0ZVRocmVhdERhc2goZGF0YS50aHJlYXRzKTt0ZXJtTGluZShk"
"YXRhLnRocmVhdHMubGVuZ3RoKycgdGhyZWF0cyDigJQgY2hlY2sgVGhyZWF0cyB0YWInLCdlcnJvcicp"
"O25vdGlmeShkYXRhLnRocmVhdHMubGVuZ3RoKycgdGhyZWF0cyBkZXRlY3RlZCEnKX0KICAgIGlmKGRh"
"dGEuaGFzX3ZvaWNlKXBsYXlWb2ljZSgpOwogIH0pCiAgLmNhdGNoKGZ1bmN0aW9uKGUpe3Rlcm1MaW5l"
"KCdFcnJvcjogJytlLm1lc3NhZ2UsJ2Vycm9yJyl9KQogIC5maW5hbGx5KGZ1bmN0aW9uKCl7c2V0TG9h"
"ZGluZyhmYWxzZSl9KTsKfQoKLyogPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PQogICBDSEFUCiAgID09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0gKi8KZnVuY3Rpb24gc2VuZENo"
"YXQoKXsKICB2YXIgaW5wPWRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdjaGF0LWlucHV0Jyk7dmFyIG1z"
"Zz1pbnAudmFsdWUudHJpbSgpO2lmKCFtc2cpcmV0dXJuO2lucC52YWx1ZT0nJzsKICB2YXIgYm94PWRv"
"Y3VtZW50LmdldEVsZW1lbnRCeUlkKCdjaGF0LW1lc3NhZ2VzJyk7CiAgdmFyIHU9ZG9jdW1lbnQuY3Jl"
"YXRlRWxlbWVudCgnZGl2Jyk7dS5jbGFzc05hbWU9J21zZyB1c2VyJzt1LmlubmVySFRNTD0nPGRpdiBj"
"bGFzcz0ibXNnLWF2YXRhciI+WU9VPC9kaXY+PGRpdiBjbGFzcz0ibXNnLWJvZHkiPicrbXNnLnJlcGxh"
"Y2UoLzwvZywnJmx0OycpLnJlcGxhY2UoLz4vZywnJmd0OycpKyc8L2Rpdj4nOwogIGJveC5hcHBlbmRD"
"aGlsZCh1KTtib3guc2Nyb2xsVG9wPWJveC5zY3JvbGxIZWlnaHQ7CiAgZmV0Y2goJy9jaGF0Jyx7bWV0"
"aG9kOidQT1NUJyxoZWFkZXJzOnsnQ29udGVudC1UeXBlJzonYXBwbGljYXRpb24vanNvbid9LGJvZHk6"
"SlNPTi5zdHJpbmdpZnkoe21lc3NhZ2U6bXNnfSl9KQogIC50aGVuKGZ1bmN0aW9uKHIpe3JldHVybiBy"
"Lmpzb24oKX0pCiAgLnRoZW4oZnVuY3Rpb24oZCl7dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgn"
"ZGl2Jyk7YS5jbGFzc05hbWU9J21zZyBhaSc7YS5pbm5lckhUTUw9JzxkaXYgY2xhc3M9Im1zZy1hdmF0"
"YXIiPkFJPC9kaXY+PGRpdiBjbGFzcz0ibXNnLWJvZHkiPicrZC5yZXNwb25zZSsnPC9kaXY+Jztib3gu"
"YXBwZW5kQ2hpbGQoYSk7Ym94LnNjcm9sbFRvcD1ib3guc2Nyb2xsSGVpZ2h0O2lmKGQuaGFzX3ZvaWNl"
"KXBsYXlWb2ljZSgpfSkKICAuY2F0Y2goZnVuY3Rpb24oKXt2YXIgZT1kb2N1bWVudC5jcmVhdGVFbGVt"
"ZW50KCdkaXYnKTtlLmNsYXNzTmFtZT0nbXNnIGFpJztlLmlubmVySFRNTD0nPGRpdiBjbGFzcz0ibXNn"
"LWF2YXRhciI+QUk8L2Rpdj48ZGl2IGNsYXNzPSJtc2ctYm9keSIgc3R5bGU9ImNvbG9yOnZhcigtLXJl"
"ZC1saWdodCkiPkNvbm5lY3Rpb24gZXJyb3IuPC9kaXY+Jztib3guYXBwZW5kQ2hpbGQoZSl9KTsKfQoK"
"LyogPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PQogICBSRVBPUlQKICAgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PSAqLwpmdW5jdGlvbiBvcGVuUmVwb3J0KCl7CiAgdmFyIG5v"
"dz1uZXcgRGF0ZSgpLnRvTG9jYWxlU3RyaW5nKCk7CiAgdmFyIHNvcnRlZD1hbGxQb3J0cy5zbGljZSgp"
"LnNvcnQoZnVuY3Rpb24oYSxiKXt2YXIgbz17Q1JJVElDQUw6MCxISUdIOjEsTUVESVVNOjIsTE9XOjN9"
"O3JldHVybihvW2Euc2V2ZXJpdHldfHwzKS0ob1tiLnNldmVyaXR5XXx8Myl8fGEucG9ydC1iLnBvcnR9"
"KTsKICB2YXIgaD0nPGRpdiBjbGFzcz0icnAtaGRyIj48ZGl2IGNsYXNzPSJycC10Ij5IQVJTSEEgdjcu"
"MCBWQVBUIFJFUE9SVDwvZGl2PjxkaXYgY2xhc3M9InJwLXMiPldlYiArIE5ldHdvcmsgKyBJbmZyYXN0"
"cnVjdHVyZSBWQVBUIFN1aXRlPC9kaXY+PGRpdiBzdHlsZT0ibWFyZ2luLXRvcDo1cHg7Zm9udC1zaXpl"
"OjEwcHg7Y29sb3I6dmFyKC0tdHgtZmFpbnQpIj5BbmFseXN0OiBIQVJTSEEgfCBUYXJnZXQ6ICcrKGxh"
"c3RUYXJnZXR8fCdNdWx0aXBsZScpKycgfCAnK25vdysnPC9kaXY+PC9kaXY+JzsKICBoKz0nPGRpdiBj"
"bGFzcz0icnAtc2VjIj48ZGl2IGNsYXNzPSJycC1zdCI+RVhFQ1VUSVZFIFNVTU1BUlk8L2Rpdj48ZGl2"
"IHN0eWxlPSJmb250LXNpemU6MTFweDtjb2xvcjp2YXIoLS10eC1tdXRlZCkiPlNjYW5zOiAnK3NjYW5D"
"b3VudCsnIMK3IFBvcnRzOiAnK2FsbFBvcnRzLmxlbmd0aCsnIMK3IFRocmVhdHM6ICcrYWxsVGhyZWF0"
"cy5sZW5ndGgrJzwvZGl2PjwvZGl2Pic7CiAgaWYoc29ydGVkLmxlbmd0aCl7aCs9JzxkaXYgY2xhc3M9"
"InJwLXNlYyI+PGRpdiBjbGFzcz0icnAtc3QiPk9QRU4gUE9SVFMgKCcrc29ydGVkLmxlbmd0aCsnKTwv"
"ZGl2Pic7c29ydGVkLmZvckVhY2goZnVuY3Rpb24ocCl7aCs9JzxkaXYgY2xhc3M9InJwLXByIj48ZGl2"
"PjxzcGFuIHN0eWxlPSJjb2xvcjp2YXIoLS1yZWQpO2ZvbnQtd2VpZ2h0OmJvbGQiPicrcC5wb3J0Kycv"
"JytwLnByb3RvKyc8L3NwYW4+PC9kaXY+PGRpdiBzdHlsZT0iY29sb3I6dmFyKC0tdHgtZGFyayk7Zm9u"
"dC13ZWlnaHQ6NjAwIj4nK3Auc2VydmljZSsnPC9kaXY+PGRpdj48c3BhbiBjbGFzcz0ic2V2ICcrcC5z"
"ZXZlcml0eSsnIj4nK3Auc2V2ZXJpdHkrJzwvc3Bhbj48L2Rpdj48ZGl2IHN0eWxlPSJjb2xvcjp2YXIo"
"LS10eC1tdXRlZCk7Zm9udC1zaXplOjEwcHgiPicrcC5kZXNjKyc8L2Rpdj48L2Rpdj4nfSk7aCs9Jzwv"
"ZGl2Pid9CiAgaWYoYWxsVGhyZWF0cy5sZW5ndGgpe2grPSc8ZGl2IGNsYXNzPSJycC1zZWMiPjxkaXYg"
"Y2xhc3M9InJwLXN0Ij5WVUxORVJBQklMSVRJRVMgKCcrYWxsVGhyZWF0cy5sZW5ndGgrJyk8L2Rpdj4n"
"O2FsbFRocmVhdHMuZm9yRWFjaChmdW5jdGlvbih0LGkpe2grPSc8ZGl2IGNsYXNzPSJycC10aCAnK3Qu"
"c2V2ZXJpdHkrJyI+PGRpdiBjbGFzcz0icnAtdG4iPicrKGkrMSkrJy4gJyt0Lm5hbWUrJyA8c3BhbiBj"
"bGFzcz0ic2V2ICcrdC5zZXZlcml0eSsnIj4nK3Quc2V2ZXJpdHkrJzwvc3Bhbj48L2Rpdj48ZGl2IGNs"
"YXNzPSJycC10ZCI+Jyt0LmRlc2MrJzwvZGl2PjxkaXYgY2xhc3M9InJwLXRmIj5GSVg6ICcrdC5maXgr"
"JzwvZGl2PjwvZGl2Pid9KTtoKz0nPC9kaXY+J30KICBpZighc29ydGVkLmxlbmd0aCYmIWFsbFRocmVh"
"dHMubGVuZ3RoKWgrPSc8ZGl2IHN0eWxlPSJjb2xvcjp2YXIoLS1zZXYtbG93KTtwYWRkaW5nOjE2cHgg"
"MCI+Tm8gZGF0YSB5ZXQuIFJ1biBzY2FucyBmaXJzdC48L2Rpdj4nOwogIGRvY3VtZW50LmdldEVsZW1l"
"bnRCeUlkKCdycCcpLmlubmVySFRNTD1oO2RvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdyZXBvcnQtbW9k"
"YWwnKS5jbGFzc0xpc3QuYWRkKCdvcGVuJyk7Cn0KZnVuY3Rpb24gY2xvc2VSZXBvcnQoKXtkb2N1bWVu"
"dC5nZXRFbGVtZW50QnlJZCgncmVwb3J0LW1vZGFsJykuY2xhc3NMaXN0LnJlbW92ZSgnb3BlbicpfQoK"
"ZnVuY3Rpb24gZG93bmxvYWRIVE1MKCl7CiAgdmFyIG5vdz1uZXcgRGF0ZSgpLnRvTG9jYWxlU3RyaW5n"
"KCk7dmFyIHNvcnRlZD1hbGxQb3J0cy5zbGljZSgpLnNvcnQoZnVuY3Rpb24oYSxiKXt2YXIgbz17Q1JJ"
"VElDQUw6MCxISUdIOjEsTUVESVVNOjIsTE9XOjN9O3JldHVybihvW2Euc2V2ZXJpdHldfHwzKS0ob1ti"
"LnNldmVyaXR5XXx8Myl8fGEucG9ydC1iLnBvcnR9KTsKICB2YXIgYj0nPCFET0NUWVBFIGh0bWw+PGh0"
"bWw+PGhlYWQ+PG1ldGEgY2hhcnNldD0iVVRGLTgiPjx0aXRsZT5IQVJTSEEgdjcuMDwvdGl0bGU+PHN0"
"eWxlPmJvZHl7Zm9udC1mYW1pbHk6bW9ub3NwYWNlO2JhY2tncm91bmQ6I2ZmZjtjb2xvcjojM2EzYTQ0"
"O3BhZGRpbmc6MzBweDttYXgtd2lkdGg6MTEwMHB4O21hcmdpbjphdXRvfWgxe2NvbG9yOiNlNjM5NDY7"
"dGV4dC1hbGlnbjpjZW50ZXJ9aDJ7Y29sb3I6I2U2Mzk0Njtmb250LXNpemU6MTJweDttYXJnaW4tdG9w"
"OjE4cHh9dGFibGV7d2lkdGg6MTAwJTtib3JkZXItY29sbGFwc2U6Y29sbGFwc2V9dGgsdGR7cGFkZGlu"
"Zzo1cHg7Ym9yZGVyLWJvdHRvbToxcHggc29saWQgI2VjZWNlZjtmb250LXNpemU6MTBweDt0ZXh0LWFs"
"aWduOmxlZnR9LmNhcmR7Ym9yZGVyLWxlZnQ6NHB4IHNvbGlkICNkOTA0Mjk7cGFkZGluZzo4cHggMTJw"
"eDttYXJnaW46NXB4IDA7YmFja2dyb3VuZDojZjdmN2Y4O2JvcmRlci1yYWRpdXM6NnB4fTwvc3R5bGU+"
"PC9oZWFkPjxib2R5Pic7CiAgYis9JzxoMT5IQVJTSEEgdjcuMCBWQVBUIFJFUE9SVDwvaDE+PHAgc3R5"
"bGU9InRleHQtYWxpZ246Y2VudGVyO2NvbG9yOiNiMGIwYmEiPicrbm93Kyc8L3A+JzsKICBpZihzb3J0"
"ZWQubGVuZ3RoKXtiKz0nPGgyPk9QRU4gUE9SVFM8L2gyPjx0YWJsZT48dHI+PHRoPlBPUlQ8L3RoPjx0"
"aD5TRVJWSUNFPC90aD48dGg+UklTSzwvdGg+PHRoPkRFU0M8L3RoPjwvdHI+Jztzb3J0ZWQuZm9yRWFj"
"aChmdW5jdGlvbihwKXtiKz0nPHRyPjx0ZD4nK3AucG9ydCsnLycrcC5wcm90bysnPC90ZD48dGQ+Jytw"
"LnNlcnZpY2UrJzwvdGQ+PHRkPicrcC5zZXZlcml0eSsnPC90ZD48dGQ+JytwLmRlc2MrJzwvdGQ+PC90"
"cj4nfSk7Yis9JzwvdGFibGU+J30KICBpZihhbGxUaHJlYXRzLmxlbmd0aCl7Yis9JzxoMj5WVUxORVJB"
"QklMSVRJRVM8L2gyPic7YWxsVGhyZWF0cy5mb3JFYWNoKGZ1bmN0aW9uKHQsaSl7Yis9JzxkaXYgY2xh"
"c3M9ImNhcmQiPjxiPicrKGkrMSkrJy4gJyt0Lm5hbWUrJzwvYj4gWycrdC5zZXZlcml0eSsnXTxwPicr"
"dC5kZXNjKyc8L3A+PHAgc3R5bGU9ImNvbG9yOiMyZDZhNGYiPkZJWDogJyt0LmZpeCsnPC9wPjwvZGl2"
"Pid9KX0KICBiKz0nPC9ib2R5PjwvaHRtbD4nOwogIHZhciBhPWRvY3VtZW50LmNyZWF0ZUVsZW1lbnQo"
"J2EnKTthLmhyZWY9VVJMLmNyZWF0ZU9iamVjdFVSTChuZXcgQmxvYihbYl0se3R5cGU6J3RleHQvaHRt"
"bCd9KSk7YS5kb3dubG9hZD0nSEFSU0hBX3Y3X1ZBUFQuaHRtbCc7YS5jbGljaygpO25vdGlmeSgnUmVw"
"b3J0IGRvd25sb2FkZWQhJyk7Cn0KZnVuY3Rpb24gZG93bmxvYWRUWFQoKXsKICB2YXIgbm93PW5ldyBE"
"YXRlKCkudG9Mb2NhbGVTdHJpbmcoKTt2YXIgdD0nSEFSU0hBIHY3LjAgVkFQVCBSRVBPUlRcbicrbm93"
"KydcblxuJzsKICBhbGxQb3J0cy5mb3JFYWNoKGZ1bmN0aW9uKHApe3QrPXAucG9ydCsnLycrcC5wcm90"
"bysnICcrcC5zZXJ2aWNlKycgWycrcC5zZXZlcml0eSsnXSAnK3AuZGVzYysnXG4nfSk7CiAgaWYoYWxs"
"VGhyZWF0cy5sZW5ndGgpe3QrPSdcblZVTE5FUkFCSUxJVElFUzpcbic7YWxsVGhyZWF0cy5mb3JFYWNo"
"KGZ1bmN0aW9uKHRoLGkpe3QrPShpKzEpKycuICcrdGgubmFtZSsnIFsnK3RoLnNldmVyaXR5KyddICcr"
"dGguZGVzYysnXG5GSVg6ICcrdGguZml4KydcblxuJ30pfQogIHZhciBhPWRvY3VtZW50LmNyZWF0ZUVs"
"ZW1lbnQoJ2EnKTthLmhyZWY9VVJMLmNyZWF0ZU9iamVjdFVSTChuZXcgQmxvYihbdF0se3R5cGU6J3Rl"
"eHQvcGxhaW4nfSkpO2EuZG93bmxvYWQ9J0hBUlNIQV92N19WQVBULnR4dCc7YS5jbGljaygpO25vdGlm"
"eSgnVFhUIGRvd25sb2FkZWQhJyk7Cn0KZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3JlcG9ydC1tb2Rh"
"bCcpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJyxmdW5jdGlvbihlKXtpZihlLnRhcmdldD09PXRoaXMp"
"Y2xvc2VSZXBvcnQoKX0pOwoKLyogPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PQogICBDSEFSVFMKICAgPT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PSAqLwpDaGFydC5kZWZhdWx0"
"cy5jb2xvcj0nIzhhOGE5Nic7Q2hhcnQuZGVmYXVsdHMuYm9yZGVyQ29sb3I9J3JnYmEoMCwwLDAsMC4w"
"NiknOwpDaGFydC5kZWZhdWx0cy5mb250LmZhbWlseT0iJ0lCTSBQbGV4IE1vbm8nLG1vbm9zcGFjZSI7"
"Q2hhcnQuZGVmYXVsdHMuZm9udC5zaXplPTEwOwpDaGFydC5kZWZhdWx0cy5wbHVnaW5zLmxlZ2VuZC5s"
"YWJlbHMuYm94V2lkdGg9MTA7Q2hhcnQuZGVmYXVsdHMucGx1Z2lucy5sZWdlbmQubGFiZWxzLnBhZGRp"
"bmc9MTQ7CgpmdW5jdGlvbiBkZXN0cm95Q2hhcnRzKG8pe09iamVjdC5rZXlzKG8pLmZvckVhY2goZnVu"
"Y3Rpb24oayl7aWYob1trXSl7b1trXS5kZXN0cm95KCk7b1trXT1udWxsfX0pfQpmdW5jdGlvbiBjYWxj"
"Umlza1Njb3JlKHAsdCl7aWYoIXAubGVuZ3RoJiYhdC5sZW5ndGgpcmV0dXJuIDA7dmFyIHM9MDtwLmZv"
"ckVhY2goZnVuY3Rpb24oeCl7aWYoeC5zZXZlcml0eT09PSdDUklUSUNBTCcpcys9MjU7ZWxzZSBpZih4"
"LnNldmVyaXR5PT09J0hJR0gnKXMrPTE1O2Vsc2UgaWYoeC5zZXZlcml0eT09PSdNRURJVU0nKXMrPTg7"
"ZWxzZSBzKz0zfSk7dC5mb3JFYWNoKGZ1bmN0aW9uKHgpe2lmKHguc2V2ZXJpdHk9PT0nQ1JJVElDQUwn"
"KXMrPTMwO2Vsc2UgaWYoeC5zZXZlcml0eT09PSdISUdIJylzKz0yMDtlbHNlIGlmKHguc2V2ZXJpdHk9"
"PT0nTUVESVVNJylzKz0xMDtlbHNlIHMrPTR9KTtyZXR1cm4gTWF0aC5taW4oMTAwLE1hdGgucm91bmQo"
"cykpfQpmdW5jdGlvbiBnZXRSaXNrQ29sb3Iocyl7aWYocz49NzUpcmV0dXJuJyNkOTA0MjknO2lmKHM+"
"PTUwKXJldHVybicjZTg1ZDA0JztpZihzPj0yNSlyZXR1cm4nI2UwOWYzZSc7cmV0dXJuJyMyZDZhNGYn"
"fQpmdW5jdGlvbiBnZXRSaXNrTGFiZWwocyl7aWYocz49NzUpcmV0dXJuJ0NSSVRJQ0FMJztpZihzPj01"
"MClyZXR1cm4nSElHSCc7aWYocz49MjUpcmV0dXJuJ01FRElVTSc7cmV0dXJuJ0xPVyd9CgpmdW5jdGlv"
"biByZWZyZXNoUmlza0NoYXJ0cygpewogIGRlc3Ryb3lDaGFydHMocmlza0NoYXJ0cyk7dmFyIGM9ZG9j"
"dW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3Jpc2stY29udGVudCcpOwogIGlmKCFhbGxQb3J0cy5sZW5ndGgm"
"JiFhbGxUaHJlYXRzLmxlbmd0aCl7Yy5pbm5lckhUTUw9JzxkaXYgY2xhc3M9ImVtcHR5LXN0YXRlIj48"
"ZGl2IGNsYXNzPSJlbXB0eS1pY28iPvCfk4o8L2Rpdj48ZGl2IGNsYXNzPSJlbXB0eS10aXRsZSI+Tm8g"
"UmlzayBEYXRhPC9kaXY+PGRpdiBjbGFzcz0iZW1wdHktc3ViIj5SdW4gc2NhbnMgZmlyc3Q8L2Rpdj48"
"L2Rpdj4nO3JldHVybn0KICB2YXIgY3JpdD0wLGhpZ2g9MCxtZWQ9MCxsb3c9MDsKICBhbGxQb3J0cy5m"
"b3JFYWNoKGZ1bmN0aW9uKHApe2lmKHAuc2V2ZXJpdHk9PT0nQ1JJVElDQUwnKWNyaXQrKztlbHNlIGlm"
"KHAuc2V2ZXJpdHk9PT0nSElHSCcpaGlnaCsrO2Vsc2UgaWYocC5zZXZlcml0eT09PSdNRURJVU0nKW1l"
"ZCsrO2Vsc2UgbG93Kyt9KTsKICBhbGxUaHJlYXRzLmZvckVhY2goZnVuY3Rpb24odCl7aWYodC5zZXZl"
"cml0eT09PSdDUklUSUNBTCcpY3JpdCsrO2Vsc2UgaWYodC5zZXZlcml0eT09PSdISUdIJyloaWdoKys7"
"ZWxzZSBpZih0LnNldmVyaXR5PT09J01FRElVTScpbWVkKys7ZWxzZSBsb3crK30pOwogIHZhciBzY29y"
"ZT1jYWxjUmlza1Njb3JlKGFsbFBvcnRzLGFsbFRocmVhdHMpLHJDPWdldFJpc2tDb2xvcihzY29yZSks"
"ckw9Z2V0Umlza0xhYmVsKHNjb3JlKTsKICB2YXIgc3ZjTWFwPXt9O2FsbFBvcnRzLmZvckVhY2goZnVu"
"Y3Rpb24ocCl7dmFyIHM9cC5zZXJ2aWNlfHwnPyc7aWYoIXN2Y01hcFtzXSlzdmNNYXBbc109e2M6MCxo"
"OjAsbTowLGw6MCx0OjB9O3N2Y01hcFtzXS50Kys7aWYocC5zZXZlcml0eT09PSdDUklUSUNBTCcpc3Zj"
"TWFwW3NdLmMrKztlbHNlIGlmKHAuc2V2ZXJpdHk9PT0nSElHSCcpc3ZjTWFwW3NdLmgrKztlbHNlIGlm"
"KHAuc2V2ZXJpdHk9PT0nTUVESVVNJylzdmNNYXBbc10ubSsrO2Vsc2Ugc3ZjTWFwW3NdLmwrK30pOwog"
"IHZhciBzTj1PYmplY3Qua2V5cyhzdmNNYXApLnNvcnQoZnVuY3Rpb24oYSxiKXtyZXR1cm4gc3ZjTWFw"
"W2JdLnQtc3ZjTWFwW2FdLnR9KS5zbGljZSgwLDEwKTsKICB2YXIgaD0nPGRpdiBjbGFzcz0iZGFzaC1n"
"cmlkIGNvbHMtMiIgc3R5bGU9Im1hcmdpbi1ib3R0b206MjBweCI+JzsKICBoKz0nPGRpdiBjbGFzcz0i"
"Y2FyZCI+PGRpdiBjbGFzcz0iY2FyZC1oZWFkZXIiPjxkaXY+PGRpdiBjbGFzcz0iY2FyZC10aXRsZSI+"
"T3ZlcmFsbCBSaXNrIFNjb3JlPC9kaXY+PC9kaXY+PC9kaXY+JzsKICBoKz0nPGRpdiBjbGFzcz0icmlz"
"ay1nYXVnZSI+PGRpdiBjbGFzcz0icmlzay1jaXJjbGUiIHN0eWxlPSJjb2xvcjonK3JDKyc7Ym9yZGVy"
"LWNvbG9yOicrckMrJzI1Ij48ZGl2IGNsYXNzPSJyaXNrLXZhbCIgc3R5bGU9ImNvbG9yOicrckMrJyI+"
"JytzY29yZSsnPC9kaXY+PGRpdiBjbGFzcz0icmlzay1sYWJlbCI+JytyTCsnPC9kaXY+PC9kaXY+JzsK"
"ICBoKz0nPGRpdiBjbGFzcz0icmlzay1kZXRhaWxzIj48ZGl2IGNsYXNzPSJyaXNrLXJvdyI+PGRpdiBj"
"bGFzcz0icmlzay1kb3QiIHN0eWxlPSJiYWNrZ3JvdW5kOnZhcigtLXJlZCkiPjwvZGl2PlBvcnRzPHNw"
"YW4gY2xhc3M9InJpc2stdmFsLXNtIiBzdHlsZT0iY29sb3I6dmFyKC0tc2V2LWhpZ2gpIj4nK2FsbFBv"
"cnRzLmxlbmd0aCsnPC9zcGFuPjwvZGl2Pic7CiAgaCs9JzxkaXYgY2xhc3M9InJpc2stcm93Ij48ZGl2"
"IGNsYXNzPSJyaXNrLWRvdCIgc3R5bGU9ImJhY2tncm91bmQ6dmFyKC0tc2V2LWNyaXQpIj48L2Rpdj5U"
"aHJlYXRzPHNwYW4gY2xhc3M9InJpc2stdmFsLXNtIiBzdHlsZT0iY29sb3I6dmFyKC0tc2V2LWNyaXQp"
"Ij4nK2FsbFRocmVhdHMubGVuZ3RoKyc8L3NwYW4+PC9kaXY+PC9kaXY+PC9kaXY+PC9kaXY+JzsKICBo"
"Kz0nPGRpdiBjbGFzcz0iY2FyZCI+PGRpdiBjbGFzcz0iY2FyZC10aXRsZSI+U2V2ZXJpdHkgRGlzdHJp"
"YnV0aW9uPC9kaXY+PGRpdiBjbGFzcz0iY2hhcnQtd3JhcCI+PGNhbnZhcyBpZD0iY2gtc2V2Ij48L2Nh"
"bnZhcz48L2Rpdj48L2Rpdj4nOwogIGgrPSc8L2Rpdj4nOwogIGlmKHNOLmxlbmd0aCl7aCs9JzxkaXYg"
"Y2xhc3M9ImRhc2gtZ3JpZCBjb2xzLTIiPjxkaXYgY2xhc3M9ImNhcmQiPjxkaXYgY2xhc3M9ImNhcmQt"
"dGl0bGUiPlJpc2sgYnkgU2VydmljZTwvZGl2PjxkaXYgY2xhc3M9ImNoYXJ0LXdyYXAiPjxjYW52YXMg"
"aWQ9ImNoLXN2YyI+PC9jYW52YXM+PC9kaXY+PC9kaXY+JzsKICBoKz0nPGRpdiBjbGFzcz0iY2FyZCI+"
"PGRpdiBjbGFzcz0iY2FyZC10aXRsZSI+UmlzayBieSBDYXRlZ29yeTwvZGl2PjxkaXYgY2xhc3M9ImNo"
"YXJ0LXdyYXAiPjxjYW52YXMgaWQ9ImNoLWNhdCI+PC9jYW52YXM+PC9kaXY+PC9kaXY+PC9kaXY+J30K"
"ICBjLmlubmVySFRNTD1oOwogIHZhciB4MT1kb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnY2gtc2V2Jyk7"
"aWYoeDEpcmlza0NoYXJ0cy5zPW5ldyBDaGFydCh4MSx7dHlwZTonZG91Z2hudXQnLGRhdGE6e2xhYmVs"
"czpbJ0NyaXRpY2FsJywnSGlnaCcsJ01lZGl1bScsJ0xvdyddLGRhdGFzZXRzOlt7ZGF0YTpbY3JpdCxo"
"aWdoLG1lZCxsb3ddLGJhY2tncm91bmRDb2xvcjpbc2V2Q29sb3JzLkNSSVRJQ0FMLHNldkNvbG9ycy5I"
"SUdILHNldkNvbG9ycy5NRURJVU0sc2V2Q29sb3JzLkxPV10sYm9yZGVyV2lkdGg6MCxob3Zlck9mZnNl"
"dDo4fV19LG9wdGlvbnM6e3Jlc3BvbnNpdmU6dHJ1ZSxtYWludGFpbkFzcGVjdFJhdGlvOmZhbHNlLGN1"
"dG91dDonNzAlJyxwbHVnaW5zOntsZWdlbmQ6e3Bvc2l0aW9uOidyaWdodCd9fX19KTsKICB2YXIgeDI9"
"ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2NoLXN2YycpO2lmKHgyJiZzTi5sZW5ndGgpcmlza0NoYXJ0"
"cy52PW5ldyBDaGFydCh4Mix7dHlwZTonYmFyJyxkYXRhOntsYWJlbHM6c04sZGF0YXNldHM6W3tsYWJl"
"bDonQ3JpdCcsZGF0YTpzTi5tYXAoZnVuY3Rpb24ocyl7cmV0dXJuIHN2Y01hcFtzXS5jfSksYmFja2dy"
"b3VuZENvbG9yOnNldkJnLkNSSVRJQ0FMLGJvcmRlckNvbG9yOnNldkNvbG9ycy5DUklUSUNBTCxib3Jk"
"ZXJXaWR0aDoxfSx7bGFiZWw6J0hpZ2gnLGRhdGE6c04ubWFwKGZ1bmN0aW9uKHMpe3JldHVybiBzdmNN"
"YXBbc10uaH0pLGJhY2tncm91bmRDb2xvcjpzZXZCZy5ISUdILGJvcmRlckNvbG9yOnNldkNvbG9ycy5I"
"SUdILGJvcmRlcldpZHRoOjF9LHtsYWJlbDonTG93JyxkYXRhOnNOLm1hcChmdW5jdGlvbihzKXtyZXR1"
"cm4gc3ZjTWFwW3NdLmx9KSxiYWNrZ3JvdW5kQ29sb3I6c2V2QmcuTE9XLGJvcmRlckNvbG9yOnNldkNv"
"bG9ycy5MT1csYm9yZGVyV2lkdGg6MX1dfSxvcHRpb25zOntyZXNwb25zaXZlOnRydWUsbWFpbnRhaW5B"
"c3BlY3RSYXRpbzpmYWxzZSxpbmRleEF4aXM6J3knLHNjYWxlczp7eDp7c3RhY2tlZDp0cnVlfSx5Ontz"
"dGFja2VkOnRydWUsZ3JpZDp7ZGlzcGxheTpmYWxzZX19fSxwbHVnaW5zOntsZWdlbmQ6e3Bvc2l0aW9u"
"Oid0b3AnLGxhYmVsczp7Ym94V2lkdGg6OH19fX19KTsKICB2YXIgY049MCxjVz0wLGNJPTA7YWxsVGhy"
"ZWF0cy5mb3JFYWNoKGZ1bmN0aW9uKHQpe3ZhciBuPXQubmFtZS50b0xvd2VyQ2FzZSgpO2lmKG4uaW5k"
"ZXhPZignc3FsJyk+PTB8fG4uaW5kZXhPZigneHNzJyk+PTB8fG4uaW5kZXhPZignaGVhZGVyJyk+PTB8"
"fG4uaW5kZXhPZignc3NsJyk+PTApY1crKztlbHNlIGlmKG4uaW5kZXhPZignc21iJyk+PTB8fG4uaW5k"
"ZXhPZignc25tcCcpPj0wfHxuLmluZGV4T2YoJ3BvcnQnKT49MCljTisrO2Vsc2UgY0krK30pOwogIHZh"
"ciB4Mz1kb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnY2gtY2F0Jyk7aWYoeDMpcmlza0NoYXJ0cy5jPW5l"
"dyBDaGFydCh4Myx7dHlwZTonZG91Z2hudXQnLGRhdGE6e2xhYmVsczpbJ05ldHdvcmsnLCdXZWInLCdJ"
"bmZyYXN0cnVjdHVyZSddLGRhdGFzZXRzOlt7ZGF0YTpbTWF0aC5tYXgoY04sU0MubmV0fHwwKSxNYXRo"
"Lm1heChjVyxTQy53ZWJ8fDApLE1hdGgubWF4KGNJLFNDLmluZnx8MCldLGJhY2tncm91bmRDb2xvcjpb"
"JyMwYTBhMGMnLCcjZTYzOTQ2JywnIzhhOGE5NiddLGJvcmRlcldpZHRoOjB9XX0sb3B0aW9uczp7cmVz"
"cG9uc2l2ZTp0cnVlLG1haW50YWluQXNwZWN0UmF0aW86ZmFsc2UsY3V0b3V0Oic3MCUnLHBsdWdpbnM6"
"e2xlZ2VuZDp7cG9zaXRpb246J3JpZ2h0J319fX0pOwp9CgpmdW5jdGlvbiByZWZyZXNoVGhyZWF0Q2hh"
"cnRzKCl7CiAgZGVzdHJveUNoYXJ0cyh0aHJlYXRDaGFydHMpO3ZhciBjPWRvY3VtZW50LmdldEVsZW1l"
"bnRCeUlkKCd0Z3JhcGgtY29udGVudCcpOwogIGlmKCFhbGxUaHJlYXRzLmxlbmd0aCYmIWFsbFBvcnRz"
"Lmxlbmd0aCl7Yy5pbm5lckhUTUw9JzxkaXYgY2xhc3M9ImVtcHR5LXN0YXRlIj48ZGl2IGNsYXNzPSJl"
"bXB0eS1pY28iPvCflbg8L2Rpdj48ZGl2IGNsYXNzPSJlbXB0eS10aXRsZSI+Tm8gVGhyZWF0IERhdGE8"
"L2Rpdj48ZGl2IGNsYXNzPSJlbXB0eS1zdWIiPlJ1biBzY2FucyBmaXJzdDwvZGl2PjwvZGl2Pic7cmV0"
"dXJufQogIHZhciBjYXRzPXtpbmplY3Rpb246MCxjb25maWc6MCxjcnlwdG86MCxleHBvc3VyZTowLGF1"
"dGg6MCxuZXR3b3JrOjB9OwogIGFsbFRocmVhdHMuZm9yRWFjaChmdW5jdGlvbih0KXt2YXIgbj10Lm5h"
"bWUudG9Mb3dlckNhc2UoKTtpZihuLmluZGV4T2YoJ3NxbCcpPj0wfHxuLmluZGV4T2YoJ3hzcycpPj0w"
"fHxuLmluZGV4T2YoJ2luamVjdCcpPj0wKWNhdHMuaW5qZWN0aW9uKys7ZWxzZSBpZihuLmluZGV4T2Yo"
"J2hlYWRlcicpPj0wfHxuLmluZGV4T2YoJ2NvcnMnKT49MHx8bi5pbmRleE9mKCdjb25maWcnKT49MClj"
"YXRzLmNvbmZpZysrO2Vsc2UgaWYobi5pbmRleE9mKCdzc2wnKT49MHx8bi5pbmRleE9mKCd0bHMnKT49"
"MCljYXRzLmNyeXB0bysrO2Vsc2UgaWYobi5pbmRleE9mKCdleHBvc3VyZScpPj0wfHxuLmluZGV4T2Yo"
"J2luZm8nKT49MCljYXRzLmV4cG9zdXJlKys7ZWxzZSBpZihuLmluZGV4T2YoJ2F1dGgnKT49MHx8bi5p"
"bmRleE9mKCdmdHAnKT49MHx8bi5pbmRleE9mKCdzc2gnKT49MCljYXRzLmF1dGgrKztlbHNlIGNhdHMu"
"bmV0d29yaysrfSk7CiAgdmFyIHN2PXtDUklUSUNBTDowLEhJR0g6MCxNRURJVU06MCxMT1c6MH07YWxs"
"VGhyZWF0cy5mb3JFYWNoKGZ1bmN0aW9uKHQpe3N2W3Quc2V2ZXJpdHldPShzdlt0LnNldmVyaXR5XXx8"
"MCkrMX0pOwogIHZhciBoPSc8ZGl2IGNsYXNzPSJkYXNoLWdyaWQgY29scy0yIiBzdHlsZT0ibWFyZ2lu"
"LWJvdHRvbToyMHB4Ij4nOwogIGgrPSc8ZGl2IGNsYXNzPSJjYXJkIj48ZGl2IGNsYXNzPSJjYXJkLXRp"
"dGxlIj5BdHRhY2sgVmVjdG9yIEFuYWx5c2lzPC9kaXY+PGRpdiBjbGFzcz0iY2hhcnQtd3JhcCI+PGNh"
"bnZhcyBpZD0iY2gtcmFkYXIiPjwvY2FudmFzPjwvZGl2PjwvZGl2Pic7CiAgaCs9JzxkaXYgY2xhc3M9"
"ImNhcmQiPjxkaXYgY2xhc3M9ImNhcmQtdGl0bGUiPlRocmVhdHMgYnkgU2V2ZXJpdHk8L2Rpdj48ZGl2"
"IGNsYXNzPSJjaGFydC13cmFwIj48Y2FudmFzIGlkPSJjaC10c2V2Ij48L2NhbnZhcz48L2Rpdj48L2Rp"
"dj48L2Rpdj4nOwogIGgrPSc8ZGl2IGNsYXNzPSJkYXNoLWdyaWQgY29scy0xIj48ZGl2IGNsYXNzPSJj"
"YXJkIj48ZGl2IGNsYXNzPSJjYXJkLXRpdGxlIj5Db21iaW5lZCBSaXNrIE92ZXJ2aWV3PC9kaXY+PGRp"
"diBjbGFzcz0iY2hhcnQtd3JhcCIgc3R5bGU9Im1pbi1oZWlnaHQ6MjIwcHgiPjxjYW52YXMgaWQ9ImNo"
"LWNvbWJvIj48L2NhbnZhcz48L2Rpdj48L2Rpdj48L2Rpdj4nOwogIGMuaW5uZXJIVE1MPWg7CiAgdmFy"
"IHIxPWRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdjaC1yYWRhcicpO2lmKHIxKXRocmVhdENoYXJ0cy5y"
"PW5ldyBDaGFydChyMSx7dHlwZToncmFkYXInLGRhdGE6e2xhYmVsczpbJ0luamVjdGlvbicsJ01pc2Nv"
"bmZpZycsJ0NyeXB0bycsJ0V4cG9zdXJlJywnQXV0aCcsJ05ldHdvcmsnXSxkYXRhc2V0czpbe2RhdGE6"
"W2NhdHMuaW5qZWN0aW9uLGNhdHMuY29uZmlnLGNhdHMuY3J5cHRvLGNhdHMuZXhwb3N1cmUsY2F0cy5h"
"dXRoLGNhdHMubmV0d29ya10sYmFja2dyb3VuZENvbG9yOidyZ2JhKDIzMCw1Nyw3MCwwLjEpJyxib3Jk"
"ZXJDb2xvcjonI2U2Mzk0NicsYm9yZGVyV2lkdGg6Mixwb2ludEJhY2tncm91bmRDb2xvcjonI2U2Mzk0"
"NicscG9pbnRSYWRpdXM6NH1dfSxvcHRpb25zOntyZXNwb25zaXZlOnRydWUsbWFpbnRhaW5Bc3BlY3RS"
"YXRpbzpmYWxzZSxzY2FsZXM6e3I6e2JlZ2luQXRaZXJvOnRydWUsZ3JpZDp7Y29sb3I6J3JnYmEoMCww"
"LDAsMC4wNiknfSx0aWNrczp7ZGlzcGxheTpmYWxzZX19fSxwbHVnaW5zOntsZWdlbmQ6e2Rpc3BsYXk6"
"ZmFsc2V9fX19KTsKICB2YXIgcjI9ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2NoLXRzZXYnKTtpZihy"
"Mil0aHJlYXRDaGFydHMucz1uZXcgQ2hhcnQocjIse3R5cGU6J2JhcicsZGF0YTp7bGFiZWxzOlsnQ3Jp"
"dGljYWwnLCdIaWdoJywnTWVkaXVtJywnTG93J10sZGF0YXNldHM6W3tkYXRhOltzdi5DUklUSUNBTCxz"
"di5ISUdILHN2Lk1FRElVTSxzdi5MT1ddLGJhY2tncm91bmRDb2xvcjpbc2V2QmcuQ1JJVElDQUwsc2V2"
"QmcuSElHSCxzZXZCZy5NRURJVU0sc2V2QmcuTE9XXSxib3JkZXJDb2xvcjpbc2V2Q29sb3JzLkNSSVRJ"
"Q0FMLHNldkNvbG9ycy5ISUdILHNldkNvbG9ycy5NRURJVU0sc2V2Q29sb3JzLkxPV10sYm9yZGVyV2lk"
"dGg6MSxib3JkZXJSYWRpdXM6OH1dfSxvcHRpb25zOntyZXNwb25zaXZlOnRydWUsbWFpbnRhaW5Bc3Bl"
"Y3RSYXRpbzpmYWxzZSxzY2FsZXM6e3g6e2dyaWQ6e2Rpc3BsYXk6ZmFsc2V9fSx5OntiZWdpbkF0WmVy"
"bzp0cnVlLHRpY2tzOntzdGVwU2l6ZToxfX19LHBsdWdpbnM6e2xlZ2VuZDp7ZGlzcGxheTpmYWxzZX19"
"fX0pOwogIHZhciByNT1kb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnY2gtY29tYm8nKTtpZihyNSl7dmFy"
"IHBTPXtDUklUSUNBTDowLEhJR0g6MCxNRURJVU06MCxMT1c6MH07YWxsUG9ydHMuZm9yRWFjaChmdW5j"
"dGlvbihwKXtwU1twLnNldmVyaXR5XT0ocFNbcC5zZXZlcml0eV18fDApKzF9KTt0aHJlYXRDaGFydHMu"
"Yz1uZXcgQ2hhcnQocjUse3R5cGU6J2JhcicsZGF0YTp7bGFiZWxzOlsnQ3JpdGljYWwnLCdIaWdoJywn"
"TWVkaXVtJywnTG93J10sZGF0YXNldHM6W3tsYWJlbDonUG9ydHMnLGRhdGE6W3BTLkNSSVRJQ0FMLHBT"
"LkhJR0gscFMuTUVESVVNLHBTLkxPV10sYmFja2dyb3VuZENvbG9yOidyZ2JhKDEwLDEwLDEyLDAuMDgp"
"Jyxib3JkZXJDb2xvcjonIzBhMGEwYycsYm9yZGVyV2lkdGg6MSxib3JkZXJSYWRpdXM6Nn0se2xhYmVs"
"OidUaHJlYXRzJyxkYXRhOltzdi5DUklUSUNBTCxzdi5ISUdILHN2Lk1FRElVTSxzdi5MT1ddLGJhY2tn"
"cm91bmRDb2xvcjoncmdiYSgyMzAsNTcsNzAsMC4xKScsYm9yZGVyQ29sb3I6JyNlNjM5NDYnLGJvcmRl"
"cldpZHRoOjEsYm9yZGVyUmFkaXVzOjZ9XX0sb3B0aW9uczp7cmVzcG9uc2l2ZTp0cnVlLG1haW50YWlu"
"QXNwZWN0UmF0aW86ZmFsc2Usc2NhbGVzOnt4OntncmlkOntkaXNwbGF5OmZhbHNlfX0seTp7YmVnaW5B"
"dFplcm86dHJ1ZSx0aWNrczp7c3RlcFNpemU6MX19fSxwbHVnaW5zOntsZWdlbmQ6e3Bvc2l0aW9uOid0"
"b3AnLGxhYmVsczp7Ym94V2lkdGg6MTB9fX19fSl9Cn0KCi8qID09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAgU0NBTiBTVEFUVVMgUE9M"
"TElORyAoU0lOR0xFIENMRUFOIFZFUlNJT04pCiAgID09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0gKi8KZnVuY3Rpb24gcG9sbFNjYW5TdGF0"
"dXMoKXsKICBmZXRjaCgnL3NjYW5fc3RhdHVzJykudGhlbihmdW5jdGlvbihyKXtyZXR1cm4gci5qc29u"
"KCl9KS50aGVuKGZ1bmN0aW9uKHMpewogICAgdmFyIGluZGljYXRvcj1kb2N1bWVudC5nZXRFbGVtZW50"
"QnlJZCgnc2Nhbi1pbmRpY2F0b3InKTsKICAgIHZhciBiYXJGaWxsPWRvY3VtZW50LmdldEVsZW1lbnRC"
"eUlkKCdzY2FuLWJhci1maWxsJyk7CiAgICB2YXIgYmFkZ2U9ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQo"
"J3NjYW4tc3RhdHVzLWJhZGdlJyk7CiAgICB2YXIgbGl2ZUNhcmQ9ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5"
"SWQoJ2xpdmUtc2Nhbi1jYXJkJyk7CiAgICB2YXIgbXA9ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2gt"
"bWluaS1wcm9ncmVzcycpOwogICAgdmFyIG1iYXI9ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2gtbWlu"
"aS1iYXInKTsKCiAgICAvKiBNaW5pIHByb2dyZXNzIGJhciAqLwogICAgaWYocy5hY3RpdmUpe21wLmNs"
"YXNzTGlzdC5hZGQoJ2FjdGl2ZScpO21iYXIuc3R5bGUud2lkdGg9cy5wZXJjZW50KyclJ30KICAgIGVs"
"c2V7bWJhci5zdHlsZS53aWR0aD1zLnBoYXNlPT09J2NvbXBsZXRlJz8nMTAwJSc6JzAlJzsKICAgICAg"
"aWYocy5waGFzZT09PSdjb21wbGV0ZScpc2V0VGltZW91dChmdW5jdGlvbigpe21wLmNsYXNzTGlzdC5y"
"ZW1vdmUoJ2FjdGl2ZScpfSwyMDAwKTsKICAgICAgZWxzZSBtcC5jbGFzc0xpc3QucmVtb3ZlKCdhY3Rp"
"dmUnKTsKICAgIH0KCiAgICAvKiBTY2FuIFN0YXR1cyB0YWIgaW5kaWNhdG9yICovCiAgICBpbmRpY2F0"
"b3IuY2xhc3NOYW1lPSdzY2FuLWluZGljYXRvcic7CiAgICBiYXJGaWxsLmNsYXNzTmFtZT0nc2Nhbi1i"
"YXItZmlsbC1saXZlJzsKICAgIGlmKHMuYWN0aXZlKXsKICAgICAgaW5kaWNhdG9yLmNsYXNzTmFtZT0n"
"c2Nhbi1pbmRpY2F0b3IgcnVubmluZyc7CiAgICAgIGJhZGdlLmNsYXNzTmFtZT0ndGFiLWJhZGdlIGxp"
"dmUnO2JhZGdlLnRleHRDb250ZW50PXMucGVyY2VudCsnJSc7CiAgICAgIGxpdmVDYXJkLnN0eWxlLmJv"
"cmRlckxlZnRDb2xvcj0ndmFyKC0tcmVkKSc7CiAgICB9IGVsc2UgaWYocy5waGFzZT09PSdjb21wbGV0"
"ZScpewogICAgICBpbmRpY2F0b3IuY2xhc3NOYW1lPSdzY2FuLWluZGljYXRvciBjb21wbGV0ZSc7CiAg"
"ICAgIGJhckZpbGwuY2xhc3NOYW1lPSdzY2FuLWJhci1maWxsLWxpdmUgY29tcGxldGUnOwogICAgICBi"
"YWRnZS5jbGFzc05hbWU9J3RhYi1iYWRnZSBkb25lJztiYWRnZS50ZXh0Q29udGVudD0nXHUyNzEzJzsK"
"ICAgICAgbGl2ZUNhcmQuc3R5bGUuYm9yZGVyTGVmdENvbG9yPSd2YXIoLS1zZXYtbG93KSc7CiAgICB9"
"IGVsc2UgaWYocy5waGFzZT09PSdlcnJvcicpewogICAgICBpbmRpY2F0b3IuY2xhc3NOYW1lPSdzY2Fu"
"LWluZGljYXRvciBlcnJvcic7CiAgICAgIGJhZGdlLmNsYXNzTmFtZT0ndGFiLWJhZGdlIHNob3cgYi1y"
"ZWQnO2JhZGdlLnRleHRDb250ZW50PSchJzsKICAgICAgbGl2ZUNhcmQuc3R5bGUuYm9yZGVyTGVmdENv"
"bG9yPSd2YXIoLS1zZXYtY3JpdCknOwogICAgfSBlbHNlIHsKICAgICAgYmFkZ2UuY2xhc3NOYW1lPSd0"
"YWItYmFkZ2UnOwogICAgICBsaXZlQ2FyZC5zdHlsZS5ib3JkZXJMZWZ0Q29sb3I9J3ZhcigtLXdoaXRl"
"LTQpJzsKICAgIH0KCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc2Nhbi1wY3QtbnVtJykudGV4"
"dENvbnRlbnQ9cy5hY3RpdmV8fHMucGhhc2U9PT0nY29tcGxldGUnP3MucGVyY2VudCsnJSc6J1x1MjAx"
"NCc7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc2Nhbi10b29sLW5hbWUnKS50ZXh0Q29udGVu"
"dD1zLnRvb2xfZGlzcGxheXx8cy50b29sfHwnXHUyMDE0JzsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRC"
"eUlkKCdzY2FuLXRhcmdldCcpLnRleHRDb250ZW50PXMudGFyZ2V0fHwnXHUyMDE0JzsKICAgIGRvY3Vt"
"ZW50LmdldEVsZW1lbnRCeUlkKCdzY2FuLWNhdCcpLnRleHRDb250ZW50PShzLmNhdGVnb3J5fHwnXHUy"
"MDE0JykudG9VcHBlckNhc2UoKTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzY2FuLWVsYXBz"
"ZWQnKS50ZXh0Q29udGVudD1zLmVsYXBzZWQrJ3MnOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQo"
"J3NjYW4tbWVzc2FnZScpLnRleHRDb250ZW50PXMubWVzc2FnZXx8J1JlYWR5IFx1MjAxNCBzZWxlY3Qg"
"YSB0b29sIHRvIGJlZ2luJzsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzY2FuLXBjdC10ZXh0"
"JykudGV4dENvbnRlbnQ9cy5wZXJjZW50KyclJzsKICAgIGJhckZpbGwuc3R5bGUud2lkdGg9cy5wZXJj"
"ZW50KyclJzsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzcy1zdWJ0aXRsZScpLnRleHRDb250"
"ZW50PXMuYWN0aXZlPydTY2FubmluZyAnK3MudGFyZ2V0KycuLi4nOnMucGhhc2U9PT0nY29tcGxldGUn"
"PydMYXN0IHNjYW4gY29tcGxldGVkJzonTm8gYWN0aXZlIHNjYW4nOwoKICAgIHZhciBwYj1kb2N1bWVu"
"dC5nZXRFbGVtZW50QnlJZCgnc2Nhbi1waGFzZS1iYWRnZScpOwogICAgcGIudGV4dENvbnRlbnQ9KHMu"
"cGhhc2V8fCdpZGxlJykudG9VcHBlckNhc2UoKTsKICAgIGlmKHMuYWN0aXZlKXtwYi5zdHlsZS5iYWNr"
"Z3JvdW5kPSd2YXIoLS1yZWQtZGltKSc7cGIuc3R5bGUuY29sb3I9J3ZhcigtLXJlZCknfQogICAgZWxz"
"ZSBpZihzLnBoYXNlPT09J2NvbXBsZXRlJyl7cGIuc3R5bGUuYmFja2dyb3VuZD0ndmFyKC0tc2V2LWxv"
"dy1iZyknO3BiLnN0eWxlLmNvbG9yPSd2YXIoLS1zZXYtbG93KSd9CiAgICBlbHNle3BiLnN0eWxlLmJh"
"Y2tncm91bmQ9J3ZhcigtLXdoaXRlLTIpJztwYi5zdHlsZS5jb2xvcj0ndmFyKC0tdHgtbXV0ZWQpJ30K"
"CiAgICB2YXIgdFM9cy5oaXN0b3J5P3MuaGlzdG9yeS5sZW5ndGg6MCx0UD0wLHRUPTAsdEQ9MDsKICAg"
"IGlmKHMuaGlzdG9yeSl7cy5oaXN0b3J5LmZvckVhY2goZnVuY3Rpb24oaCl7dFArPWgucG9ydHN8fDA7"
"dFQrPWgudGhyZWF0c3x8MDt0RCs9aC5lbGFwc2VkfHwwfSl9CiAgICBkb2N1bWVudC5nZXRFbGVtZW50"
"QnlJZCgnc3MtdG90YWwnKS50ZXh0Q29udGVudD10UzsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlk"
"KCdzcy1wb3J0cycpLnRleHRDb250ZW50PXRQOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3Nz"
"LXRocmVhdHMnKS50ZXh0Q29udGVudD10VDsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzcy1h"
"dmcnKS50ZXh0Q29udGVudD10Uz4wPyh0RC90UykudG9GaXhlZCgxKSsncyc6JzBzJzsKCiAgICBpZihz"
"Lmhpc3RvcnkmJnMuaGlzdG9yeS5sZW5ndGgpewogICAgICB2YXIgcm93cz0nJzsKICAgICAgcy5oaXN0"
"b3J5LmZvckVhY2goZnVuY3Rpb24oaCl7CiAgICAgICAgcm93cys9Jzx0cj48dGQgc3R5bGU9ImNvbG9y"
"OnZhcigtLXNldi1sb3cpO2ZvbnQtd2VpZ2h0OjcwMCI+XHUyNzEzIERvbmU8L3RkPic7CiAgICAgICAg"
"cm93cys9Jzx0ZCBzdHlsZT0iZm9udC13ZWlnaHQ6NjAwO2NvbG9yOnZhcigtLXR4LWRhcmspIj4nK2gu"
"dG9vbCsnPC90ZD4nOwogICAgICAgIHJvd3MrPSc8dGQgc3R5bGU9ImZvbnQtZmFtaWx5OklCTSBQbGV4"
"IE1vbm8sbW9ub3NwYWNlO2ZvbnQtc2l6ZToxMXB4O2NvbG9yOnZhcigtLXJlZCkiPicraC50YXJnZXQr"
"JzwvdGQ+JzsKICAgICAgICByb3dzKz0nPHRkIHN0eWxlPSJmb250LWZhbWlseTpJQk0gUGxleCBNb25v"
"LG1vbm9zcGFjZTtmb250LXdlaWdodDo3MDAiPicraC5lbGFwc2VkKydzPC90ZD4nOwogICAgICAgIHJv"
"d3MrPSc8dGQ+JytoLnBvcnRzKyc8L3RkPjx0ZD4nK2gudGhyZWF0cysnPC90ZD4nOwogICAgICAgIHJv"
"d3MrPSc8dGQgc3R5bGU9ImNvbG9yOnZhcigtLXR4LWZhaW50KSI+JytoLnRpbWUrJzwvdGQ+PC90cj4n"
"OwogICAgICB9KTsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3NzLWhpc3RvcnktdGFibGUn"
"KS5pbm5lckhUTUw9cm93czsKICAgIH0KCiAgICBpZihzLmFjdGl2ZSAmJiBsYXN0UGhhc2UhPT0nc2Nh"
"bm5pbmcnICYmIGxhc3RQaGFzZSE9PSdpbml0aWFsaXppbmcnICYmIGxhc3RQaGFzZSE9PSdhbmFseXpp"
"bmcnKXsKICAgICAgc3dpdGNoVGFiKCdzY2Fuc3RhdHVzJyxkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxs"
"KCcudGFiLWJ0bicpWzVdKTsKICAgIH0KICAgIGxhc3RQaGFzZT1zLnBoYXNlOwogIH0pLmNhdGNoKGZ1"
"bmN0aW9uKCl7fSk7Cn0Kc2V0SW50ZXJ2YWwocG9sbFNjYW5TdGF0dXMsODAwKTsKCi8qIEtFWUJPQVJE"
"IFNIT1JUQ1VUUyAqLwpkb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCdrZXlkb3duJyxmdW5jdGlvbihl"
"KXsKICBpZihlLmN0cmxLZXkmJmUua2V5PT09Jy8nKXtlLnByZXZlbnREZWZhdWx0KCk7ZG9jdW1lbnQu"
"Z2V0RWxlbWVudEJ5SWQoJ3Rvb2wtc2VhcmNoJykuZm9jdXMoKX0KfSk7Cjwvc2NyaXB0PgoKPC9ib2R5"
"Pgo8L2h0bWw+Cg=="
)


# ═══════════════════════════════════════════════════════
# EMBEDDED UI — SINGLE FILE, NO EXTERNAL DEPENDENCIES
# ═══════════════════════════════════════════════════════
def get_html():
    import base64
    return base64.b64decode(_HTML_B64).decode("utf-8")

@app.route("/")
def index():
    return Response(get_html(), mimetype="text/html")

if __name__ == "__main__":
    print("""
================================================================
  H.A.R.S.H.A AI v7.0 - FULL VAPT SUITE
  Web VAPT + Network VAPT + Infrastructure VAPT
================================================================
  Open browser: http://localhost:5000
  TIP: chmod +s /usr/bin/nmap
  TIP: pip install wafw00f sqlmap
================================================================
    """)
    app.run(debug=False, host="0.0.0.0", port=5000)
