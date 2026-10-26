#!/usr/bin/env python3
"""
Threat Intelligence Aggregator
Collects indicators of compromise (IoCs) from AlienVault OTX and optionally
enriches them with VirusTotal reputation data.

This tool makes read-only API requests. It does not scan hosts, exploit systems,
or perform actions against the indicators.
"""
from __future__ import annotations

import argparse
import base64
import csv
import ipaddress
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

OTX_BASE = "https://otx.alienvault.com/api/v1"
VT_BASE = "https://www.virustotal.com/api/v3"
USER_AGENT = "StudentThreatIntelAggregator/1.0 (educational project)"
HASH_RE = re.compile(r"^(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def classify_indicator(value: str) -> str:
    """Identify supported IoC types without making a network request."""
    value = value.strip()
    try:
        ipaddress.ip_address(value)
        return "IPv4" if ":" not in value else "IPv6"
    except ValueError:
        pass
    if HASH_RE.fullmatch(value):
        return "hash"
    if value.lower().startswith(("http://", "https://")):
        return "URL"
    # A lightweight domain check; not intended as full URL/domain validation.
    candidate = value.rstrip(".")
    if "." in candidate and " " not in candidate and "/" not in candidate:
        return "domain"
    return "unknown"


def vt_resource_path(indicator: str, indicator_type: str) -> str | None:
    """Build a VirusTotal v3 read-only resource path."""
    if indicator_type in ("IPv4", "IPv6"):
        return f"ip_addresses/{indicator}"
    if indicator_type == "domain":
        return f"domains/{indicator}"
    if indicator_type == "hash":
        return f"files/{indicator}"
    if indicator_type == "URL":
        encoded = base64.urlsafe_b64encode(indicator.encode("utf-8")).decode("ascii").rstrip("=")
        return f"urls/{encoded}"
    return None


def request_json(url: str, headers: dict[str, str], timeout: int = 20) -> dict[str, Any]:
    response = requests.get(url, headers=headers, timeout=timeout)
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise ValueError("The API returned an unexpected response format.")
    return payload


def fetch_otx_indicators(limit: int = 5) -> list[dict[str, Any]]:
    """Fetch IoCs from the user's subscribed AlienVault OTX pulses."""
    api_key = os.getenv("OTX_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("OTX_API_KEY is not set. Set it or use --demo.")
    url = f"{OTX_BASE}/pulses/subscribed?limit={limit}"
    headers = {"X-OTX-API-KEY": api_key, "User-Agent": USER_AGENT}
    payload = request_json(url, headers)
    rows: list[dict[str, Any]] = []
    for pulse in payload.get("results", []):
        pulse_name = pulse.get("name", "Unnamed pulse")
        pulse_id = pulse.get("id", "")
        for item in pulse.get("indicators", []):
            value = str(item.get("indicator", "")).strip()
            if value:
                rows.append({
                    "indicator": value,
                    "type": classify_indicator(value),
                    "source": "AlienVault OTX",
                    "pulse": pulse_name,
                    "pulse_id": pulse_id,
                    "collected_at": utc_now(),
                })
    # Keep unique indicators while preserving order.
    seen: set[str] = set()
    unique = []
    for row in rows:
        key = row["indicator"].lower()
        if key not in seen:
            seen.add(key)
            unique.append(row)
    return unique


def enrich_virustotal(indicator: str, indicator_type: str) -> dict[str, Any]:
    """Look up an IoC using VirusTotal's read-only v3 API."""
    api_key = os.getenv("VT_API_KEY", "").strip()
    path = vt_resource_path(indicator, indicator_type)
    if not api_key:
        return {"vt_status": "skipped: VT_API_KEY not set"}
    if path is None:
        return {"vt_status": "skipped: unsupported indicator type"}
    headers = {"x-apikey": api_key, "User-Agent": USER_AGENT}
    try:
        payload = request_json(f"{VT_BASE}/{path}", headers)
        attrs = payload.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "vt_status": "ok",
            "vt_reputation": attrs.get("reputation", ""),
            "vt_malicious": stats.get("malicious", 0),
            "vt_suspicious": stats.get("suspicious", 0),
            "vt_harmless": stats.get("harmless", 0),
            "vt_undetected": stats.get("undetected", 0),
            "vt_last_analysis": attrs.get("last_analysis_date", ""),
        }
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "unknown"
        if status == 404:
            return {"vt_status": "not found"}
        if status == 429:
            return {"vt_status": "rate limited"}
        return {"vt_status": f"HTTP error {status}"}
    except (requests.RequestException, ValueError) as exc:
        return {"vt_status": f"request error: {type(exc).__name__}"}


def demo_records() -> list[dict[str, Any]]:
    """Clearly marked, non-live examples for demonstrating output offline."""
    examples = [
        ("198.51.100.23", "IPv4", "Documentation example address"),
        ("example.org", "domain", "Reserved example domain"),
        ("44d88612fea8a8f36de82e1278abb02f", "hash", "Commonly used training hash example"),
        ("https://example.org/login", "URL", "Reserved example domain URL"),
    ]
    now = utc_now()
    return [{
        "indicator": value,
        "type": kind,
        "source": "DEMO DATA — NOT LIVE INTELLIGENCE",
        "pulse": note,
        "pulse_id": "",
        "collected_at": now,
        "vt_status": "demo: no API request made",
        "vt_reputation": "",
        "vt_malicious": "",
        "vt_suspicious": "",
        "vt_harmless": "",
        "vt_undetected": "",
        "vt_last_analysis": "",
    } for value, kind, note in examples]


def write_json(records: list[dict[str, Any]], path: Path) -> None:
    path.write_text(json.dumps({
        "generated_at": utc_now(),
        "record_count": len(records),
        "records": records,
    }, indent=2, ensure_ascii=False), encoding="utf-8")


def write_csv(records: list[dict[str, Any]], path: Path) -> None:
    fields = [
        "indicator", "type", "source", "pulse", "pulse_id", "collected_at",
        "vt_status", "vt_reputation", "vt_malicious", "vt_suspicious",
        "vt_harmless", "vt_undetected", "vt_last_analysis",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Collect IoCs from AlienVault OTX and optionally enrich with VirusTotal."
    )
    parser.add_argument("--limit", type=int, default=5, help="Number of subscribed OTX pulses to request (1-20).")
    parser.add_argument("--max-enrich", type=int, default=10, help="Maximum IoCs to query in VirusTotal (0-50).")
    parser.add_argument("--json", dest="json_path", default="threat_intel_report.json", help="JSON output filename.")
    parser.add_argument("--csv", dest="csv_path", default="threat_intel_report.csv", help="CSV output filename.")
    parser.add_argument("--indicator", action="append", default=[], help="Add a specific IP, domain, URL, or file hash. Repeatable.")
    parser.add_argument("--demo", action="store_true", help="Use clearly labelled local demo data; no API calls.")
    parser.add_argument("--delay", type=float, default=1.0, help="Seconds between VirusTotal requests.")
    args = parser.parse_args()

    if not 1 <= args.limit <= 20:
        parser.error("--limit must be between 1 and 20")
    if not 0 <= args.max_enrich <= 50:
        parser.error("--max-enrich must be between 0 and 50")
    if args.delay < 0:
        parser.error("--delay cannot be negative")

    if args.demo:
        records = demo_records()
    else:
        records: list[dict[str, Any]] = []
        try:
            records.extend(fetch_otx_indicators(args.limit))
        except (RuntimeError, requests.RequestException, ValueError) as exc:
            print(f"[warning] OTX collection failed: {exc}", file=sys.stderr)

        for value in args.indicator:
            value = value.strip()
            if value:
                records.append({
                    "indicator": value,
                    "type": classify_indicator(value),
                    "source": "User supplied",
                    "pulse": "",
                    "pulse_id": "",
                    "collected_at": utc_now(),
                })

        seen: set[str] = set()
        deduped = []
        for row in records:
            key = row["indicator"].lower()
            if key not in seen:
                seen.add(key)
                deduped.append(row)
        records = deduped

        enrich_count = 0
        for row in records:
            if enrich_count >= args.max_enrich:
                row.setdefault("vt_status", "skipped: max enrichment limit reached")
                continue
            if row.get("type") == "unknown":
                row["vt_status"] = "skipped: unsupported indicator type"
                continue
            result = enrich_virustotal(row["indicator"], row["type"])
            row.update(result)
            # Count every attempted VirusTotal lookup, including 404/429 responses,
            # so the configured request cap cannot be bypassed by failed lookups.
            if os.getenv("VT_API_KEY", "").strip() and vt_resource_path(row["indicator"], row["type"]) is not None:
                enrich_count += 1
                if args.delay and enrich_count < args.max_enrich:
                    time.sleep(args.delay)

    json_path, csv_path = Path(args.json_path), Path(args.csv_path)
    write_json(records, json_path)
    write_csv(records, csv_path)

    print("=" * 68)
    print("THREAT INTELLIGENCE AGGREGATOR")
    print(f"Generated: {utc_now()}")
    print(f"Indicators collected: {len(records)}")
    print(f"JSON report: {json_path.resolve()}")
    print(f"CSV report : {csv_path.resolve()}")
    print("-" * 68)
    if not records:
        print("No indicators collected. Configure OTX_API_KEY or provide --indicator values.")
    for index, row in enumerate(records, start=1):
        print(f"{index:02d}. {row.get('indicator')} [{row.get('type')}]")
        print(f"    Source: {row.get('source', 'Unknown')}")
        print(f"    VirusTotal: {row.get('vt_status', 'not queried')}")
        if row.get("vt_status") == "ok":
            print(f"    Malicious detections: {row.get('vt_malicious', 0)}")
    print("=" * 68)
    print("Note: reputation data is advisory and can be incomplete or incorrect.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
