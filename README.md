# CyberAI: Threat Triage Tool

CyberAI is a Python tool that helps you decide quickly whether a **link**, **email**, or **PDF** looks safe. It runs several security checks at once and gives a plain verdict (**Clean**, **Suspicious**, or **Malware**) along with the reasons behind it.

Use it from the command line or in a small web page on your own computer. It can also save your results as a PDF report.

## What it can check

| You give it | What CyberAI does |
|---|---|
| **A URL** | Looks up the link's VirusTotal report, reads its DNS records, finds who registered the domain (RDAP), checks the mail-server IPs against spam blocklists, and flags warning signs such as many hyphens, very long domains, unusual characters, or words like "login" and "verify". |
| **An email** (an address, pasted raw text, or an `.eml` file) | Checks the sender's domain for look-alike or spoofed names, looks for SPF and DMARC records, verifies DKIM signatures (for `.eml` files), spots phishing-style wording and a Reply-To that differs from the sender, and checks IPs in the headers against spam blocklists. |
| **A PDF** | Extracts the links found inside the file. |

Every result is also saved to a local database (`threat_history.db`) so you can review it later.

## How the verdict is decided

Each finding adds points to a score:

- VirusTotal: 2 points per "malicious" detection, 1 point per "suspicious"
- Each spam-blocklist listing: 2 points
- URL warning signs: up to 2 points
- Each email alert: 1 point

A score of **5 or more** is **Malware**, **1 to 4** is **Suspicious**, and **0** is **Clean**.

## Getting started

You need Python 3.8 or newer.

```bash
git clone https://github.com/Muhammad-Huzaifa-Shafique/CyberAI.git
cd CyberAI
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Add your VirusTotal key (optional)

The VirusTotal check needs a free API key from [virustotal.com](https://www.virustotal.com). Give it to the tool through an environment variable, and never paste keys into the code:

```bash
export VIRUSTOTAL_API_KEY="your-key-here"          # macOS / Linux
$env:VIRUSTOTAL_API_KEY = "your-key-here"          # Windows PowerShell
```

Without a key, everything else still works and the VirusTotal part is skipped.

## Using it

```bash
python CyberAI.py                  # interactive command-line mode
python CyberAI.py --mode serve     # web page at http://127.0.0.1:8080
python CyberAI.py --mode history   # show the 10 most recent results
python CyberAI.py --save-pdf       # create a PDF report from saved history, then exit
```

In command-line mode, choose `url`, `email`, or `pdf`, then paste a link, an email address, raw email text, or a file path. Type `exit` to quit. In web mode, `--host` and `--port` change the address.

### Reports

- When you leave command-line mode, a report is saved as `Threat Detection Results.pdf` in your Downloads folder.
- In web mode, the latest report can be downloaded at `/download`.

### Optional: your own trusted domains

The look-alike check compares domains against a built-in list (pittstate.edu, paypal.com, google.com, microsoft.com, apple.com). To use your own list, add a `trusted_domains.json` file next to `CyberAI.py`:

```json
["yourcompany.com", "google.com", "paypal.com"]
```

## Project files

| File | Purpose |
|---|---|
| `CyberAI.py` | The whole tool: analysis checks, command line, web page, and PDF reports |
| `requirements.txt` | Python packages to install |

## Good to know

- It needs an internet connection (DNS, RDAP, and VirusTotal lookups). Free VirusTotal keys have usage limits.
- VirusTotal checks use the existing report for a URL; new URLs are not submitted for scanning.
- Results are meant for quick triage, not final verdicts. Informational notes (like "SPF found") currently count toward an email's score, so a "Suspicious" label is a cue to look closer.
- PDF mode currently only extracts links; it does not scan them yet.
- This tool supports learning and first-pass checks. It does not replace antivirus or professional security tools.

## Author

Made by [Muhammad Huzaifa Shafique](https://github.com/Muhammad-Huzaifa-Shafique).
