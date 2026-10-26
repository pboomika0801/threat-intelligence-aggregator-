# Threat Intelligence Aggregator

A college-level cybersecurity project that collects Indicators of Compromise (IoCs) from AlienVault Open Threat Exchange (OTX) and optionally enriches them with VirusTotal reputation data. Results are saved as JSON and CSV files.

## Features

- Retrieves indicators from subscribed AlienVault OTX pulses.
- Accepts manually supplied IPv4/IPv6 addresses, domains, URLs, and file hashes.
- Enriches supported indicators through VirusTotal's read-only API.
- Deduplicates indicators and records collection timestamps.
- Exports results to JSON and CSV.
- Includes offline demo mode that makes no network/API calls.
- Uses API keys from environment variables rather than storing secrets in source code.

## Requirements

- Python 3.10 or newer
- Internet connection for live collection
- AlienVault OTX API key for pulse collection
- VirusTotal API key for enrichment (optional)
- Python package listed in `requirements.txt`

## Installation

### Windows (PowerShell)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Set API keys for the current PowerShell session:

```powershell
$env:OTX_API_KEY="YOUR_OTX_API_KEY"
$env:VT_API_KEY="YOUR_VIRUSTOTAL_API_KEY"
```

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
export OTX_API_KEY="YOUR_OTX_API_KEY"
export VT_API_KEY="YOUR_VIRUSTOTAL_API_KEY"
```

Obtain keys only from the official provider accounts:
- AlienVault OTX: https://otx.alienvault.com/
- VirusTotal: https://www.virustotal.com/

Do not commit API keys to Git or share them in screenshots or reports. The program does not need both keys: OTX is used for pulse collection; VirusTotal is optional.

## How to run

### 1. Offline demo (recommended first run)

This mode uses local example values, makes no API requests, and is safe to run without keys:

```bash
python main.py --demo
```

It creates `threat_intel_report.json` and `threat_intel_report.csv` in the current directory. The sample values are explicitly marked as demo data, not live threat intelligence.

### 2. Live OTX collection and VirusTotal enrichment

```bash
python main.py --limit 5 --max-enrich 10
```

- `--limit`: number of subscribed OTX pulses to request (1–20).
- `--max-enrich`: maximum indicators to look up in VirusTotal (0–50).
- `--delay`: delay in seconds between successful VirusTotal lookups; default is 1 second.
- `--json`: JSON output path.
- `--csv`: CSV output path.

### 3. Add an indicator manually

```bash
python main.py --indicator 8.8.8.8 --indicator example.org
```

Use only indicators you are authorized to investigate. If OTX is not configured, manually supplied indicators can still be processed, but VirusTotal enrichment requires `VT_API_KEY`.

### 4. Custom output filenames

```bash
python main.py --demo --json demo.json --csv demo.csv
```

## Example output

The exact values depend on API responses and may change. A demo run will resemble:

```text
====================================================================
THREAT INTELLIGENCE AGGREGATOR
Generated: 2026-10-26T12:00:00+00:00
Indicators collected: 4
JSON report: /your/path/threat_intel_report.json
CSV report : /your/path/threat_intel_report.csv
--------------------------------------------------------------------
01. 198.51.100.23 [IPv4]
    Source: DEMO DATA — NOT LIVE INTELLIGENCE
    VirusTotal: demo: no API request made
02. example.org [domain]
    Source: DEMO DATA — NOT LIVE INTELLIGENCE
    VirusTotal: demo: no API request made
...
====================================================================
Note: reputation data is advisory and can be incomplete or incorrect.
```

The timestamp and full paths will differ on your computer.

## Output formats

- **JSON**: includes generation timestamp, record count, and a list of indicator records.
- **CSV**: spreadsheet-friendly table with indicator type, source, pulse details, collection time, and enrichment fields.

## Testing

Run the following checks from the project folder:

```bash
python -m unittest -v
python main.py --demo
```

The unit tests are in `test_main.py` if supplied separately; if it is not present in your copy, use the manual checks below:
1. `python main.py --demo` exits successfully and writes JSON and CSV.
2. Open both output files and confirm four demo records appear.
3. Run `python main.py --indicator example.org --max-enrich 0`; it should write a report even if API keys are absent.
4. Try an invalid `--limit 0`; the program should reject the value with a clear argument error.
5. With valid keys, check that live records show an appropriate VirusTotal status such as `ok`, `not found`, or `rate limited`.

## Troubleshooting

- **OTX_API_KEY is not set**: live OTX collection will be skipped with a warning. Set the key in your terminal session.
- **VirusTotal skipped**: set `VT_API_KEY`; without it the program will not send VT requests.
- **HTTP 429 / rate limited**: wait and retry later; reduce `--max-enrich` and respect provider limits.
- **No indicators collected**: configure OTX or pass `--indicator` values.
- **Network/TLS errors**: check your connection, system clock, and Python certificates.

## Ethical and legal limitations

- This project is for education, defensive analysis, and authorized threat-intelligence work only.
- It performs read-only API lookups. It does not probe, scan, exploit, or disrupt third-party systems.
- Do not use the tool to harass, target, or interfere with any person or organization.
- Use provider APIs according to their terms, rate limits, and privacy policies.
- Do not upload confidential, personal, or organization-sensitive indicators to third-party services without permission.
- A malicious/suspicious score is not proof of malicious activity. Verify findings using multiple sources and human review.
- Keep API keys secret and rotate any key that is accidentally exposed.

## Project structure

```text
threat-intelligence-aggregator/
├── main.py
├── requirements.txt
├── README.md
└── Project_Report.pdf
```

## Project summary

The application combines threat indicators from a community threat feed with reputation metadata from a second provider. It demonstrates API integration, data normalization, deduplication, exception handling, command-line design, and structured report generation.
