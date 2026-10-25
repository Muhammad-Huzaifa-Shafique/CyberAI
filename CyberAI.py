#!/usr/bin/env python3
"""
Threat Triage Tool (final merged)

Features included:
 - CLI + Flask UI for URL, PDF, Email analysis
 - VirusTotal URL check (with your API key)
 - DNSBL checks (Spamhaus, Spamcop, SORBS)
 - Domain info (DNS + PTR + MX + TXT + SOA)
 - RDAP lookup + parser for many TLDs (com/net/org/edu/gov/uk + fallback)
 - SPF & DMARC lookups
 - DKIM verification for .eml (dkimpy)
 - Spoofing detection: typosquatting, suspicious subdomains, homograph
 - Phishing heuristics: suspicious wording, Reply-To mismatch
 - SQLite logging (threat_history.db)
 - Classification: Clean / Suspicious / Malware
 - PDF report generation: saved to ~/Downloads/Threat Detection Results.pdf on exit (and downloadable via Flask)
"""

import os
import argparse
import requests
import base64
import re
import sqlite3
import socket
import difflib
import json
from datetime import datetime, timezone
from urllib.parse import urlparse
from PyPDF2 import PdfReader
from flask import Flask, request, render_template_string, send_file
import dns.resolver
import dns.reversename
import tldextract

# optional libs
try:
    import dkim
except Exception:
    dkim = None

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
except Exception:
    # reportlab optional but required for PDF output
    raise

# ---------------- Config ----------------
# Read the VirusTotal API key from the environment (never hard-code keys in source code).
# Without a key, the VirusTotal check is skipped and everything else still works.
VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
HEADERS_VT = {"x-apikey": VT_API_KEY} if VT_API_KEY else {}
TIMEOUT = 20
DB_PATH = "threat_history.db"
PDF_FILENAME = "Threat Detection Results.pdf"
DOWNLOADS_DIR = os.path.join(os.path.expanduser("~"), "Downloads")
PDF_PATH = os.path.join(DOWNLOADS_DIR, PDF_FILENAME)

# load trusted domains from JSON if available, else fallback
TRUSTED_DOMAINS_FILE = "trusted_domains.json"
if os.path.exists(TRUSTED_DOMAINS_FILE):
    try:
        with open(TRUSTED_DOMAINS_FILE, "r", encoding="utf-8") as tf:
            TRUSTED_DOMAINS = json.load(tf)
    except Exception:
        TRUSTED_DOMAINS = ["pittstate.edu", "paypal.com", "google.com", "microsoft.com", "apple.com"]
else:
    TRUSTED_DOMAINS = ["pittstate.edu", "paypal.com", "google.com", "microsoft.com", "apple.com"]

# session results accumulate for PDF output on exit
SESSION_RESULTS = []

# ---------------- SQLite ----------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        type TEXT,
        input TEXT,
        classification TEXT,
        reasons TEXT
    )""")
    conn.commit(); conn.close()

def log_result(result, classification, reasons):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO results (timestamp,type,input,classification,reasons) VALUES (?,?,?,?,?)",
              (datetime.now(timezone.utc).isoformat(),
               result.get("type"),
               str(result.get("url") or result.get("input"))[:200],
               classification,
               "; ".join(reasons)))
    conn.commit(); conn.close()
    # also add to session for PDF
    SESSION_RESULTS.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": result.get("type"),
        "input": str(result.get("url") or result.get("input"))[:400],
        "classification": classification,
        "reasons": reasons
    })

def fetch_history(limit=10):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id,timestamp,type,input,classification,reasons FROM results ORDER BY id DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    return rows

# ---------------- Helpers ----------------
def safe_request(method, url, **kwargs):
    try:
        return requests.request(method, url, timeout=TIMEOUT, **kwargs)
    except Exception as e:
        # keep stable behavior
        return None

def extract_urls_from_text(text):
    return list(dict.fromkeys(re.findall(r"https?://[^\s'\"<>]+", text or "")))

def is_ipv4(s: str) -> bool:
    try:
        socket.inet_aton(s)
        return True
    except Exception:
        return False

def is_homograph(domain):
    try:
        domain.encode("ascii")
        return False
    except UnicodeEncodeError:
        return True

def check_typosquatting(domain):
    alerts = []
    ext = tldextract.extract(domain)
    if not ext.suffix:
        base = domain
    else:
        base = f"{ext.domain}.{ext.suffix}"
    # suspicious extra subdomain if base is trusted
    if base in TRUSTED_DOMAINS and ext.subdomain:
        alerts.append(f"Extra subdomain '{ext.subdomain}' before trusted base '{base}' (possible spoofing)")
    # similarity to trusted list
    for safe in TRUSTED_DOMAINS:
        ratio = difflib.SequenceMatcher(None, base, safe).ratio()
        if ratio > 0.75 and base != safe:
            alerts.append(f"Domain '{base}' looks similar to '{safe}' (possible spoofing)")
    return alerts

# ---------------- VirusTotal (URL) ----------------
def vt_url_scan(url):
    if not VT_API_KEY:
        return None, "VIRUSTOTAL_API_KEY not set"
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        resp = safe_request("GET", api_url, headers=HEADERS_VT)
        if not resp:
            return None, "No response from VirusTotal."
        if resp.status_code != 200:
            return None, f"VirusTotal returned {resp.status_code}"
        return resp.json(), ""
    except Exception as e:
        return None, f"VT exception: {e}"

# ---------------- DNSBL ----------------
def check_dnsbl(ip, dnsbls=None):
    if dnsbls is None:
        dnsbls = ["zen.spamhaus.org","bl.spamcop.net","dnsbl.sorbs.net"]
    hits = []
    try:
        reversed_ip = ".".join(reversed(ip.split(".")))
    except Exception:
        return ["Invalid IP format"]

    for dnsbl in dnsbls:
        query = f"{reversed_ip}.{dnsbl}"
        try:
            socket.gethostbyname(query)
            hits.append(f"Listed in {dnsbl}")
        except socket.gaierror:
            pass
    return hits if hits else ["Clean"]

def dnsbl_for_domain(domain: str):
    results = []
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8","8.8.4.4","1.1.1.1"]
    resolver.timeout = 5; resolver.lifetime = 5
    ips = set()

    # MX first
    try:
        mx_answers = resolver.resolve(domain, "MX")
        for r in mx_answers:
            host = str(r.exchange).rstrip(".")
            try:
                ip = socket.gethostbyname(host)
                ips.add(ip)
            except Exception:
                pass
    except Exception as e:
        results.append(f"MX lookup error: {e}")

    # If no MX IPs, fall back to A record
    if not ips:
        try:
            a_answers = resolver.resolve(domain, "A")
            for r in a_answers:
                ips.add(str(r))
        except Exception as e:
            results.append(f"A lookup error: {e}")

    if not ips:
        results.append("No IP found to DNSBL-check")
        return results

    for ip in sorted(ips):
        hits = check_dnsbl(ip)
        for h in hits:
            results.append(f"{ip}: {h}")
    return results

def dnsbl_from_raw_email(text: str):
    results = []
    ips = set(re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", text or ""))
    ips = {ip for ip in ips if is_ipv4(ip)}
    if ips:
        for ip in sorted(ips):
            hits = check_dnsbl(ip)
            for h in hits:
                results.append(f"{ip}: {h}")
    else:
        results.append("No IPv4 addresses found in headers")

    # From domain
    m = re.search(r"From:\s*.*<[^@]+@([^>]+)>", text, re.IGNORECASE) or \
        re.search(r"From:\s*([^\s<]+)@([^\s>]+)", text, re.IGNORECASE)
    from_domain = None
    if m:
        if m.lastindex == 2:
            from_domain = m.group(2)
        else:
            from_field = m.group(0)
            m2 = re.search(r"@([A-Za-z0-9.-]+)", from_field)
            if m2:
                from_domain = m2.group(1)

    if from_domain:
        results.append(f"From-domain DNSBL for {from_domain}:")
        results.extend(dnsbl_for_domain(from_domain))

    return results

# ---------------- Domain Info (DNS + RDAP) ----------------
def get_dns_info(domain):
    out = {"A": [], "MX": [], "NS": [], "TXT": [], "SOA": None, "PTR": []}
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8","8.8.4.4","1.1.1.1"]
    resolver.timeout = 5; resolver.lifetime = 5

    try:
        answers = resolver.resolve(domain,"A")
        out["A"] = [str(r) for r in answers]
        for ip in out["A"]:
            try:
                rev = dns.reversename.from_address(ip)
                ptr = resolver.resolve(rev,"PTR")[0].to_text()
                out["PTR"].append(f"{ip} -> {ptr}")
            except Exception as e:
                out["PTR"].append(f"{ip} -> PTR error: {e}")
    except Exception as e:
        out["A"] = [f"DNS A error: {e}"]

    try:
        answers = resolver.resolve(domain,"MX")
        out["MX"] = [f"{r.preference} {r.exchange}" for r in answers]
    except Exception as e:
        out["MX"] = [f"DNS MX error: {e}"]

    try:
        answers = resolver.resolve(domain,"NS")
        out["NS"] = [str(r.target) for r in answers]
    except Exception as e:
        out["NS"] = [f"DNS NS error: {e}"]

    try:
        answers = resolver.resolve(domain,"TXT")
        out["TXT"] = [b" ".join(r.strings).decode(errors="ignore") for r in answers]
    except Exception as e:
        out["TXT"] = [f"DNS TXT error: {e}"]

    try:
        soa = resolver.resolve(domain,"SOA")[0].to_text()
        out["SOA"] = soa
    except Exception as e:
        out["SOA"] = f"DNS SOA error: {e}"

    return out

def format_dns_table(dns_info):
    rows = []
    for key, values in dns_info.items():
        if isinstance(values, list):
            for v in values:
                rows.append((key, v))
        else:
            rows.append((key, values))
    if not rows:
        return "[No DNS data]"
    col1_width = max(len(r[0]) for r in rows)
    out_lines = []
    out_lines.append("+" + "-"*(col1_width+2) + "+" + "-"*70 + "+")
    out_lines.append(f"| {'Type'.ljust(col1_width)} | Records".ljust(74) + "|")
    out_lines.append("+" + "-"*(col1_width+2) + "+" + "-"*70 + "+")
    for k, v in rows:
        s = str(v)
        if len(s) <= 70:
            out_lines.append(f"| {k.ljust(col1_width)} | {s}")
        else:
            out_lines.append(f"| {k.ljust(col1_width)} | {s[:67]}...")
    out_lines.append("+" + "-"*(col1_width+2) + "+" + "-"*70 + "+")
    return "\n".join(out_lines)

def get_rdap(domain):
    tld = domain.split(".")[-1].lower()
    servers = {
        "com": f"https://rdap.verisign.com/com/v1/domain/{domain}",
        "net": f"https://rdap.verisign.com/net/v1/domain/{domain}",
        "org": f"https://rdap.publicinterestregistry.net/rdap/org/domain/{domain}",
        "edu": f"https://rdap.educause.edu/domain/{domain}",
        "gov": f"https://rdap.dotgov.gov/domain/{domain}",
        "uk":  f"https://rdap.nominet.uk/domain/{domain}"
    }
    rdap_url = servers.get(tld, f"https://rdap.org/domain/{domain}")
    try:
        r = requests.get(rdap_url, timeout=10)
        if r.status_code == 200:
            return r.json()
        return {"error": f"RDAP returned {r.status_code} from {rdap_url}"}
    except Exception as e:
        return {"error": f"RDAP request failed: {e}"}

def parse_rdap(rdap_json):
    if not rdap_json or "error" in rdap_json:
        return {"error": rdap_json.get("error", "No RDAP data")}
    info = {"registrar": "Unknown", "created": None, "expires": None, "status": []}
    for ent in rdap_json.get("entities", []):
        roles = ent.get("roles", [])
        if roles and "registrar" in roles:
            vcard = ent.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
                for item in vcard[1]:
                    if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                        info["registrar"] = item[3]
                        break
    if info["registrar"] == "Unknown":
        reg_obj = rdap_json.get("registrar") or {}
        if isinstance(reg_obj, dict):
            nm = reg_obj.get("name") or reg_obj.get("legalName")
            if nm: info["registrar"] = nm
    for ev in rdap_json.get("events", []):
        act = ev.get("eventAction")
        if act == "registration":
            info["created"] = ev.get("eventDate")
        elif act == "expiration":
            info["expires"] = ev.get("eventDate")
    st = rdap_json.get("status")
    if isinstance(st, list): info["status"] = st
    return info

# ---------------- Heuristics ----------------
def url_heuristics(domain: str):
    if not domain:
        return []
    heur = []
    if domain.count("-") > 3:
        heur.append("many-hyphens")
    if len(domain.split(".")) > 3:
        heur.append("long-subdomain-chain")
    if len(domain) > 40:
        heur.append("very-long-domain")
    if any(ord(c) > 127 for c in domain):
        heur.append("non-ascii (possible IDN homograph)")
    sus_keywords = ["login","secure","verify","update","account","paypal","bank","gift","free","promo"]
    if any(k in domain.lower() for k in sus_keywords):
        heur.append("suspicious-keyword")
    return heur

# ---------------- DKIM verification ----------------
def verify_dkim_bytes(raw_bytes):
    if dkim is None:
        return {"valid": None, "error": "dkimpy not installed"}
    try:
        ok = dkim.verify(raw_bytes)
        return {"valid": bool(ok)}
    except Exception as e:
        return {"valid": None, "error": str(e)}

# ---------------- Analysis Wrappers ----------------
def analyze_website(url):
    vt_result, vt_err = vt_url_scan(url)
    parsed = urlparse(url)
    # domain extraction robust
    domain = parsed.hostname or parsed.netloc or url
    if isinstance(domain, str):
        domain = domain.lstrip("[]")
    heuristics = url_heuristics(domain)
    dns_info = get_dns_info(domain)
    rdap_raw = get_rdap(domain)
    rdap_info = parse_rdap(rdap_raw) if isinstance(rdap_raw, dict) and "error" not in rdap_raw else rdap_raw
    dnsbl = dnsbl_for_domain(domain)
    return {"type":"url","url":url,"domain":domain,
            "vt_result":vt_result,"vt_error":vt_err,"heuristics":heuristics,
            "dns_info":dns_info,"rdap_info":rdap_info,"dnsbl":dnsbl}

def analyze_pdf(path_or_url):
    urls=[]
    if os.path.isfile(path_or_url):
        try:
            reader=PdfReader(path_or_url)
            for p in reader.pages:
                try:
                    urls.extend(extract_urls_from_text(p.extract_text() or ""))
                except Exception:
                    pass
        except Exception:
            pass
    else:
        urls = extract_urls_from_text(path_or_url)
    return {"type":"pdf","input":path_or_url,"extracted_urls":urls}

def check_spf_dmarc(domain):
    results = []
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8","1.1.1.1"]
    try:
        txt_records = resolver.resolve(domain,"TXT")
        spf = [r.to_text() for r in txt_records if "v=spf1" in r.to_text().lower()]
        if spf:
            results.append("SPF found")
        else:
            results.append("No SPF record")
    except Exception:
        results.append("SPF lookup failed")
    try:
        txt_records = resolver.resolve(f"_dmarc.{domain}","TXT")
        dmarc = [r.to_text() for r in txt_records if "v=dmarc1" in r.to_text().lower()]
        if dmarc:
            results.append("DMARC found")
        else:
            results.append("No DMARC record")
    except Exception:
        results.append("DMARC lookup failed")
    return results

def analyze_email(text_or_path):
    """
    Handles:
     - single email address (plain): runs MX->IP DNSBL, SPF/DMARC, typosquatting/homograph
     - raw email text or .eml file: parses Received IPs -> DNSBL, From domain checks, SPF/DMARC, DKIM (if .eml bytes)
    """
    out = {"type":"email","input":text_or_path,"sender":None,"extracted_urls":[],"dnsbl":[],"mode":None,"alerts":[],"dkim":None}

    # Load content
    raw_bytes = None
    if os.path.isfile(text_or_path):
        # try to read bytes and text
        try:
            with open(text_or_path, "rb") as fb:
                raw_bytes = fb.read()
        except Exception:
            raw_bytes = None
        try:
            with open(text_or_path, "r", errors="ignore") as f:
                text = f.read()
        except Exception:
            text = raw_bytes.decode("utf-8", errors="ignore") if raw_bytes else ""
        out["mode"] = "eml-file"
    else:
        text = text_or_path
        out["mode"] = "raw-or-address"

    out["extracted_urls"] = extract_urls_from_text(text)

    # If looks like a single email address
    if "\n" not in text.strip() and text.count("@") == 1 and " " not in text.strip():
        addr = text.strip()
        out["sender"] = addr
        domain = addr.split("@")[-1]
        out["dnsbl"] = dnsbl_for_domain(domain)
        out["alerts"].extend(check_typosquatting(domain))
        if is_homograph(domain):
            out["alerts"].append("Homograph Unicode domain (possible spoofing)")
        out["alerts"].extend(check_spf_dmarc(domain))
    else:
        # Raw email flow
        out["dnsbl"] = dnsbl_from_raw_email(text)
        # Extract From:
        m = re.search(r"From:\s*.*<([^>]+)>", text, re.IGNORECASE) or \
            re.search(r"From:\s*([^\s<]+@[^\s>]+)", text, re.IGNORECASE)
        if m:
            out["sender"] = m.group(1) if m.lastindex == 1 else m.group(0)
        # Domain checks
        if out["sender"] and "@" in out["sender"]:
            domain = out["sender"].split("@")[-1]
            out["alerts"].extend(check_typosquatting(domain))
            if is_homograph(domain):
                out["alerts"].append("Homograph Unicode domain (possible spoofing)")
            out["alerts"].extend(check_spf_dmarc(domain))
        # DKIM verify if we have raw bytes and dkim available
        if raw_bytes and dkim is not None:
            try:
                dk = verify_dkim_bytes(raw_bytes)
                out["dkim"] = dk
                if dk.get("valid") is True:
                    out["alerts"].append("DKIM: valid")
                elif dk.get("valid") is False:
                    out["alerts"].append("DKIM: invalid")
                elif dk.get("error"):
                    out["alerts"].append(f"DKIM error: {dk.get('error')}")
            except Exception as e:
                out["dkim"] = {"valid": None, "error": str(e)}
        # content heuristics
        if re.search(r"(verify|reset|urgent|bank|paypal|password|account|suspend|click here)", text, re.IGNORECASE):
            out["alerts"].append("Suspicious wording in content (phishing-like)")
        # Reply-To mismatch
        reply_to_match = re.search(r"Reply-To:\s*([^\r\n]+)", text, re.IGNORECASE)
        if reply_to_match and out["sender"]:
            reply_to = reply_to_match.group(1).strip()
            if out["sender"] not in reply_to:
                out["alerts"].append("Reply-To differs from From (spoofing risk)")

    return out

# ---------------- Classification ----------------
def classify_threat(result):
    reasons, score = [], 0
    vt = result.get("vt_result")
    if vt:
        try:
            stats = vt["data"]["attributes"]["last_analysis_stats"]
            mal, sus = stats.get("malicious",0), stats.get("suspicious",0)
            if mal+sus:
                reasons.append(f"VirusTotal: malicious={mal}, suspicious={sus}")
            score += (mal*2 + sus)
        except Exception:
            reasons.append("VirusTotal: no stats")
    elif result.get("vt_error"):
        reasons.append(f"VirusTotal error: {result['vt_error']}")

    if result.get("dnsbl"):
        for hit in result["dnsbl"]:
            if isinstance(hit, str) and "Listed in" in hit:
                reasons.append(hit); score += 2
            elif isinstance(hit, str) and "No IP found" in hit:
                reasons.append(hit)

    if result.get("heuristics"):
        reasons.append(f"Heuristics: {', '.join(result['heuristics'])}")
        score += min(2, len(result["heuristics"]))

    if result.get("alerts"):
        for a in result["alerts"]:
            reasons.append(a)
        score += len(result["alerts"])

    if score >= 5:
        return "Malware", reasons
    if score >= 1:
        return "Suspicious", reasons
    return "Clean", reasons

# ---------------- PDF report generation ----------------
def save_results_to_pdf(session_results, path=PDF_PATH):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    doc = SimpleDocTemplate(path, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    story.append(Paragraph("<b>Threat Detection Results</b>", styles["Title"]))
    story.append(Spacer(1, 12))
    for r in session_results:
        story.append(Paragraph(f"<b>Time:</b> {r.get('timestamp')}", styles["Heading4"]))
        story.append(Paragraph(f"<b>Type:</b> {r.get('type')}  &nbsp; <b>Classification:</b> {r.get('classification')}", styles["Normal"]))
        story.append(Paragraph(f"<b>Input:</b> {r.get('input')}", styles["Normal"]))
        story.append(Paragraph("<b>Reasons:</b>", styles["Normal"]))
        for line in r.get("reasons", []):
            story.append(Paragraph(f"- {line}", styles["Normal"]))
        story.append(Spacer(1, 10))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Generated by Threat Triage Tool", styles["Italic"]))
    doc.build(story)
    return path

# ---------------- CLI ----------------
def cli_loop(save_pdf_on_exit=True):
    try:
        while True:
            t = input("\nType (url/pdf/email or exit): ").strip().lower()
            if t == "exit":
                break
            v = input("Input (URL, file path, raw email, or email address): ").strip()
            if v == "exit":
                break

            if t=="url":
                res = analyze_website(v)
            elif t=="pdf":
                res = analyze_pdf(v)
            elif t=="email":
                res = analyze_email(v)
            else:
                print("[!] Invalid type"); continue

            classification, reasons = classify_threat(res)
            print(f"\n[+] Classification: {classification}")
            for r in reasons:
                print(" -", r)

            # additional printing for details
            if t=="url":
                print("\n[+] Domain Info (DNS):")
                print(format_dns_table(res["dns_info"]))
                print("\n[+] RDAP Info:")
                rdap = res["rdap_info"]
                if isinstance(rdap, dict) and "error" in rdap:
                    print(" Error:", rdap["error"])
                else:
                    print(" Registrar:", rdap.get("registrar", "Unknown"))
                    print(" Created:", rdap.get("created"))
                    print(" Expires:", rdap.get("expires"))
                    print(" Status:", rdap.get("status"))
                if res.get("dnsbl"):
                    print("\n[+] DNSBL (domain):")
                    for h in res["dnsbl"]:
                        print("  -", h)

            if t=="email":
                print("\n[+] Email Mode:", res.get("mode"))
                print(" Sender:", res.get("sender"))
                if res.get("dnsbl"):
                    print("\n[+] DNSBL (email):")
                    for h in res["dnsbl"]:
                        print("  -", h)
                if res.get("alerts"):
                    print("\n[+] Alerts:")
                    for a in res["alerts"]:
                        print("  -", a)
                if res.get("dkim"):
                    print("\n[+] DKIM:", res["dkim"])

            log_result(res, classification, reasons)

            again = input("\nCheck another? (y/n): ").strip().lower()
            if again != "y": break
    finally:
        # Save PDF on exit if requested and there are session results
        if save_pdf_on_exit and SESSION_RESULTS:
            try:
                path = save_results_to_pdf(SESSION_RESULTS, PDF_PATH)
                print(f"[+] PDF report saved to: {path}")
            except Exception as e:
                print("[!] Failed to save PDF:", e)

# ---------------- Flask ----------------
FLASK_TEMPLATE = """<!doctype html><html><body>
<h2>Threat Triage</h2>
<form method=post>
<select name=type>
  <option value=url>URL</option>
  <option value=pdf>PDF</option>
  <option value=email>Email</option>
</select>
<br><br>
<textarea name=input_text rows=8 cols=80 placeholder="Paste URL, PDF path/URL, raw email text, or an email address"></textarea><br>
<button type=submit>Analyze</button>
</form>
{% if classification %}
<hr>
<h3>Classification: {{classification}}</h3>
{% if reasons %}<ul>{% for r in reasons %}<li>{{r}}</li>{% endfor %}</ul>{% endif %}
{% if t == 'url' %}
<h3>DNS</h3><pre>{{dns_table}}</pre>
<h3>RDAP</h3>
{% if rdap_error %}<p>Error: {{rdap_error}}</p>{% else %}
<p><b>Registrar:</b> {{rdap.registrar}}<br>
<b>Created:</b> {{rdap.created}}<br>
<b>Expires:</b> {{rdap.expires}}<br>
<b>Status:</b> {{rdap.status}}</p>
{% endif %}
{% if dnsbl %}<h3>DNSBL</h3><ul>{% for h in dnsbl %}<li>{{h}}</li>{% endfor %}</ul>{% endif %}
{% endif %}
{% if t == 'email' %}
<p><b>Mode:</b> {{email_mode}} &nbsp; <b>Sender:</b> {{sender}}</p>
{% if dnsbl %}<h3>DNSBL</h3><ul>{% for h in dnsbl %}<li>{{h}}</li>{% endfor %}</ul>{% endif %}
{% if alerts %}<h3>Alerts</h3><ul>{% for a in alerts %}<li>{{a}}</li>{% endfor %}</ul>{% endif %}
{% if dkim %}<h3>DKIM</h3><pre>{{dkim}}</pre>{% endif %}
{% endif %}
{% endif %}
</body></html>"""

def create_app():
    app = Flask(__name__)
    app.config["LAST_PDF"] = None

    @app.route("/", methods=["GET","POST"])
    def index():
        classification=None; reasons=[]; dns_table=""; rdap={}; rdap_error=None; dnsbl=[]; t=None; email_mode=None; sender=None; alerts=None; dkim_res=None
        if request.method=="POST":
            t=request.form.get("type"); txt=request.form.get("input_text","").strip()
            if t=="url" and txt:
                res=analyze_website(txt)
                classification, reasons = classify_threat(res)
                dns_table = format_dns_table(res["dns_info"])
                rdap = res["rdap_info"]
                if isinstance(rdap, dict) and "error" in rdap: rdap_error = rdap["error"]
                dnsbl = res.get("dnsbl", [])
            elif t=="pdf" and txt:
                res=analyze_pdf(txt)
                classification, reasons = classify_threat(res)
            elif t=="email" and txt:
                res=analyze_email(txt)
                classification, reasons = classify_threat(res)
                email_mode = res.get("mode"); sender = res.get("sender"); dnsbl = res.get("dnsbl", []); alerts = res.get("alerts", []); dkim_res = res.get("dkim")
            else:
                res = {"error":"invalid input"}; classification="Unknown"; reasons=["invalid input"]

            log_result(res, classification, reasons)
            # Save a quick PDF for this session update (not required, but keep last)
            try:
                p = save_results_to_pdf(SESSION_RESULTS, PDF_PATH) if SESSION_RESULTS else None
                app.config["LAST_PDF"] = p
            except Exception:
                app.config["LAST_PDF"] = None

        return render_template_string(FLASK_TEMPLATE,
                                      classification=classification, reasons=reasons,
                                      dns_table=dns_table, rdap=rdap, rdap_error=rdap_error, dnsbl=dnsbl,
                                      t=t, email_mode=email_mode, sender=sender, alerts=alerts, dkim=dkim_res)

    @app.route("/download")
    def download_pdf():
        if os.path.exists(PDF_PATH):
            return send_file(PDF_PATH, as_attachment=True)
        return "No PDF available", 404

    return app

# ---------------- Main ----------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("cli","serve","history"), default="cli")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8080, type=int)
    parser.add_argument("--save-pdf", action="store_true", help="save PDF immediately from DB/session and exit")
    args = parser.parse_args()

    init_db()

    if args.save_pdf:
        # generate PDF from DB (all or last session)
        rows = fetch_history(limit=200)
        rows_json = []
        for rid, ts, t, inp, cls, reasons in rows:
            rows_json.append({"timestamp": ts, "type": t, "input": inp, "classification": cls, "reasons": reasons.split("; ") if reasons else []})
        if rows_json:
            try:
                save_results_to_pdf(rows_json, PDF_PATH)
                print(f"[+] PDF saved to {PDF_PATH}")
            except Exception as e:
                print("[!] Failed to save PDF:", e)
        else:
            print("[!] No history to save.")
        return

    if args.mode == "cli":
        cli_loop(save_pdf_on_exit=True)
    elif args.mode == "history":
        rows = fetch_history()
        for rid, ts, t, inp, cls, reasons in rows:
            print(f"\nID:{rid} | Time:{ts} | Type:{t}")
            print(f"Input: {inp}")
            print(f"Classification: {cls}")
            if reasons: print(f"Reasons: {reasons}")
    elif args.mode == "serve":
        app = create_app()
        print(f"UI available at http://{args.host}:{args.port}")
        app.run(host=args.host, port=args.port)

if __name__ == "__main__":
    main()
