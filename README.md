# NTLMEnum

NTLM authentication endpoint enumerator for penetration testing. Discovers HTTP(S) endpoints that support NTLM authentication and extracts Active Directory domain information from NTLM Type 2 (Challenge) responses.

Built to address the shortcomings of [NTLMRecon](https://github.com/pwnfoo/NTLMRecon) and nmap's [http-ntlm-info](https://nmap.org/nsedoc/scripts/http-ntlm-info.html) NSE script.

## Features

- **96 built-in endpoint paths** covering Exchange, SharePoint, ADFS, Skype for Business/Lync, RD Web, SCCM/MECM, WSUS, ADCS, SSRS, WinRM, TFS/Azure DevOps, and more
- **Full NTLM Type 2 challenge parsing** — extracts NetBIOS names, DNS names, forest name, OS version/build, and server timestamp
- **SPNEGO/Negotiate unwrapping** — handles servers that advertise `Negotiate` instead of bare `NTLM`
- **Proxy-Authenticate support** — detects NTLM on both standard and proxy authentication headers
- **NTLMv1 detection** — flags endpoints where extended session security is absent (weak authentication)
- **Clock skew calculation** — compares server timestamp against local time
- **Async concurrent scanning** — configurable thread pool for fast subnet sweeps
- **HTTP and HTTPS** — scans both schemes by default, with custom port support
- **Multiple HTTP methods** — probe with GET, POST, OPTIONS, or any combination
- **CIDR and range input** — expands `10.0.0.0/24` and `10.0.0.1-10` notation
- **Multiple output formats** — table, JSON, CSV, and JSONL
- **Proxy routing** — send traffic through Burp Suite or other intercepting proxies
- **Web crawling** — spider targets to discover endpoints beyond the static wordlist (`--crawl`)
- **Custom wordlists** — extend or replace the built-in path list
- **Custom headers** — add cookies, tokens, or other headers to requests

## Installation

```bash
# Clone and set up a virtual environment
cd /opt/NTLMEnum
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

The only external dependency is [httpx](https://www.python-httpx.org/) with HTTP/2 support.

## Usage

```
ntlmenum [-h] [-t TARGET] [-T TARGETS_FILE] [--scheme {http,https,both}]
          [--ports PORTS [PORTS ...]] [--methods METHODS [METHODS ...]]
          [--threads THREADS] [--timeout TIMEOUT] [--verify-ssl]
          [--proxy PROXY] [--user-agent USER_AGENT] [-H HEADER]
          [-w WORDLIST] [--custom-paths-only]
          [--crawl] [--crawl-depth N] [--crawl-max-pages N]
          [-o OUTPUT] [-f {table,json,csv,jsonl}] [-v] [-q] [--debug]
          [--version]
```

### Examples

```bash
# Scan a single host
ntlmenum -t mail.example.com

# Scan a subnet on specific ports
ntlmenum -t 10.0.0.0/24 --ports 80 443 8443

# Scan with multiple HTTP methods and verbose output
ntlmenum -t exchange.corp.local --methods GET POST OPTIONS -v

# Save JSON results to a file
ntlmenum -t 10.0.0.0/24 -f json -o results.json

# Scan through Burp Suite
ntlmenum -t target.corp.local --proxy http://127.0.0.1:8080

# Use a custom path wordlist alongside built-in paths
ntlmenum -t target.corp.local -w custom_paths.txt

# Use only your custom wordlist
ntlmenum -t target.corp.local -w custom_paths.txt --custom-paths-only

# Scan from a target list file
ntlmenum -T targets.txt --threads 50 -f csv -o results.csv

# HTTP only, IP range shorthand
ntlmenum -t 10.0.0.1-20 --scheme http

# Add a custom header (e.g., a cookie)
ntlmenum -t target.corp.local -H "Cookie: session=abc123"

# Crawl a target to discover endpoints beyond the static wordlist
ntlmenum -t mail.example.com --crawl

# Crawl with deeper depth and higher page limit
ntlmenum -t mail.example.com --crawl --crawl-depth 5 --crawl-max-pages 500

# Crawl-only mode (no built-in wordlist, just crawled paths)
ntlmenum -t mail.example.com --crawl --custom-paths-only
```

### Target Formats

| Format | Example | Description |
|--------|---------|-------------|
| Hostname | `mail.example.com` | Scans both HTTP and HTTPS on default ports |
| IP address | `10.0.0.5` | Single host |
| Host:port | `10.0.0.5:8443` | Specific port |
| CIDR | `10.0.0.0/24` | Expands to all host addresses |
| IP range | `10.0.0.1-10` | Last-octet range shorthand |
| Full URL | `https://mail.example.com/owa/` | Scans that URL plus all built-in paths |

### Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| Table | `-f table` | Human-readable summary (default) |
| JSON | `-f json` | Structured JSON with all fields |
| CSV | `-f csv` | Spreadsheet-friendly flat format |
| JSONL | `-f jsonl` | One JSON object per line, for log pipelines |

## Sample Output

```
================================================================================
  NTLM ENUMERATION RESULTS
================================================================================

  Target: CORP\YOURSERVER
  ──────────────────────────────────────────────────────────────────────────
  FQDN:           yourserver.corp.example.com
  DNS Domain:     corp.example.com
  DNS Forest:     example.com
  NetBIOS Domain: CORP
  NetBIOS Name:   YOURSERVER
  OS Version:     10.0.17763 (Windows 10/11 / Server 2016+)
  Server Time:    2026-10-21T14:30:00+00:00
  Clock Skew:     +3 seconds
  ⚠ NTLMv1 Supported (weak authentication)

  DISCOVERED ENDPOINTS
  ──────────────────────────────────────────────────────────────────────────
  URL                                         Method   Category   Auth Header
  ──────────────────────────────────────────────────────────────────────────
  https://mail.example.com/owa/               GET      Exchange   www-authenticate
  https://mail.example.com/EWS/Exchange.asmx  GET      Exchange   www-authenticate
  https://mail.example.com/Autodiscover/...   GET      Exchange   www-authenticate
  https://mail.example.com/mapi/emsmdb/       GET      MAPI       www-authenticate
  https://mail.example.com/PowerShell/        GET      Exchange   www-authenticate
  https://mail.example.com/Rpc/               GET      Exchange   www-authenticate

  Total: 6 endpoint(s) found
================================================================================
```

## Extracted Information

Every NTLM endpoint that responds with a valid Type 2 challenge yields:

| Field | Source | Description |
|-------|--------|-------------|
| NetBIOS Computer Name | AV_PAIR 0x0001 | Server's NetBIOS name |
| NetBIOS Domain Name | AV_PAIR 0x0002 | AD domain short name |
| DNS Computer Name | AV_PAIR 0x0003 | Server FQDN |
| DNS Domain Name | AV_PAIR 0x0004 | AD domain FQDN |
| DNS Tree Name | AV_PAIR 0x0005 | AD forest name |
| OS Version | Version field | Major.Minor.Build (e.g., 10.0.19041) |
| OS Product | Version mapping | Human-readable name (e.g., Windows 10/11 / Server 2016+) |
| Server Timestamp | AV_PAIR 0x0007 | UTC time from FILETIME, with clock skew |
| Negotiate Flags | Flags field | Full flag list in verbose mode |
| NTLMv1 Support | Flag analysis | Warns when extended session security is absent |

## Built-in Path Coverage

The 96 built-in paths are organized by product category:

| Category | Paths | Products |
|----------|-------|----------|
| Exchange | 20 | OWA, ECP, EWS, ActiveSync, Autodiscover, MAPI, PowerShell, RPC, OAB, Unified Messaging |
| SharePoint | 10 | \_vti\_bin, \_layouts, \_api, \_windows |
| ADFS / SSO | 7 | ADFS WIA, Windows Transport, IWA |
| Skype / Lync | 22 | Address Book, MCX, Dialin, Reach, RGS, UCWA, WebTicket, Persistent Chat |
| ADCS | 5 | Certificate Services, CertEnroll, OCSP |
| RD Web | 3 | RD Web Access, RPC Proxy |
| SCCM / WSUS | 10 | Distribution Points, Client Web Service, Auth Services |
| SSRS | 3 | SQL Server Reporting Services |
| WinRM | 2 | WS-Management |
| TFS / Azure DevOps | 2 | Team Foundation Server |
| IIS / Generic | 5 | Root path, aspnet\_client, api, remote |

## Crawling

Static wordlists will always miss custom or non-standard NTLM endpoints. The `--crawl` flag enables a web spider that discovers URLs dynamically before probing them for NTLM authentication.

### How It Works

1. The crawler starts from the target's root page (or the URL you provide)
2. It follows same-origin links found in HTML (`<a href>`, `<form action>`, `<script src>`, etc.) and common JavaScript patterns (`fetch('/api/...')`)
3. Discovered URLs are merged with the built-in wordlist (deduplicated)
4. Every URL — from the wordlist and the crawl — is then probed for NTLM auth

### Crawl Options

| Flag | Default | Description |
|------|---------|-------------|
| `--crawl` | off | Enable crawling |
| `--crawl-depth` | 3 | Maximum link-following depth from the start page |
| `--crawl-max-pages` | 200 | Maximum number of pages to fetch per target |

### Crawl Modes

| Mode | Command | Behavior |
|------|---------|----------|
| Wordlist only | `ntlmenum -t target` | Checks only the 96 built-in paths (default) |
| Wordlist + crawl | `ntlmenum -t target --crawl` | Checks built-in paths plus crawl-discovered URLs |
| Crawl only | `ntlmenum -t target --crawl --custom-paths-only` | Checks only crawl-discovered URLs (no wordlist) |
| Custom + crawl | `ntlmenum -t target --crawl -w paths.txt` | Checks custom wordlist plus crawl-discovered URLs |

The crawler skips static assets (images, fonts, CSS, JS files, archives, binaries) and stays within the target's origin — it won't follow links to external sites.

## Improvements Over Existing Tools

### vs NTLMRecon

| Limitation | NTLMRecon | NTLMEnum |
|------------|-----------|----------|
| OS version extraction | Not implemented | Full version + build + product name |
| Server timestamp | Not parsed | Parsed with clock skew calculation |
| Negotiate/SPNEGO | Skipped if no bare `NTLM` | SPNEGO unwrap extracts NTLM from Negotiate tokens |
| Proxy-Authenticate | Not checked | Checked alongside WWW-Authenticate |
| Initial probe method | HEAD only | Configurable (GET, POST, OPTIONS, any combination) |
| URL schemes | Forces HTTPS | HTTP, HTTPS, or both |
| Path coverage | ~50 paths | 96 paths + custom wordlist support |
| Missing products | No SharePoint, RDWeb, SCCM, WSUS, MAPI, WinRM | All included |
| Output formats | Broken CSV only | Table, JSON, CSV, JSONL |
| CIDR validation | Regex accepts invalid octets | stdlib `ipaddress` module |
| NTLMv1 detection | None | Flags weak authentication config |
| Proxy support | None | `--proxy` flag |
| Custom ports | None | `--ports` flag |
| Endpoint discovery | Static wordlist only | Static wordlist + web crawling (`--crawl`) |
| Dead code / broken flags | `--random-user-agent`, `--force-all`, `--output-type` all broken | Clean implementation, all flags functional |

### vs nmap http-ntlm-info

| Limitation | http-ntlm-info | NTLMEnum |
|------------|----------------|----------|
| Paths scanned | Single path (`/` or one user-specified) | 96 built-in + custom wordlist |
| Batch scanning | Single host per invocation | Multi-target with CIDR/range expansion |
| HTTP methods | GET only | Configurable |
| Output formats | nmap text only | JSON, CSV, JSONL, table |
| Proxy-Authenticate | Not checked | Checked |
| Negotiate/SPNEGO | Not unwrapped | SPNEGO unwrap |
| NTLMv1 detection | Not flagged | Flagged |
| Timestamp reporting | Used internally for clock skew, not shown | Shown in output + clock skew |
| Negotiate flags | Not reported | Full flag list in verbose mode |
| Endpoint discovery | No crawling | Static wordlist + web crawling |

## Project Structure

```
NTLMEnum/
├── ntlmenum/
│   ├── __init__.py      # Package version
│   ├── __main__.py      # python -m ntlmenum entry point
│   ├── cli.py           # Argument parsing, target expansion, CLI runner
│   ├── crawler.py       # Async web crawler for endpoint discovery
│   ├── ntlm.py          # NTLM Type 1/2 construction, parsing, SPNEGO unwrap
│   ├── output.py        # Table, JSON, CSV, JSONL formatters
│   ├── paths.py         # Built-in endpoint path wordlist (96 paths)
│   └── scanner.py       # Async HTTP scanner engine
├── pyproject.toml       # Package metadata and dependencies
├── requirements.txt     # pip requirements
└── README.md
```

## Requirements

- Python 3.10+
- httpx with HTTP/2 support (installed automatically)

## Legal

This tool is intended for authorized penetration testing and security assessments only. Obtain proper authorization before scanning any systems you do not own. Unauthorized access to computer systems is illegal.
