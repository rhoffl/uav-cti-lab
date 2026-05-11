#!/usr/bin/env python3
"""
UAV CTI Lab — CTI-to-Suricata Rule Exporter
File: scripts/cti/cti_to_suricata.py

Pulls indicators from OpenCTI and generates Suricata rules that
operationalize them in the IDS pipeline — the core CTI "correlate"
stage that drives the detection improvement shown in our results.

Citations:
  [11] OASIS (2021). STIX 2.1 Standard.
  [12] Schlette et al. (2021). IEEE Comms Surveys 23(4).
  [10] Strom et al. (2018). MITRE ATT&CK. MITRE MTR180035.
"""

import logging
import os
import re
import time
from datetime import datetime

import requests

log = logging.getLogger("cti-to-suricata")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

OPENCTI_URL   = os.getenv("OPENCTI_URL",   "http://localhost:8080")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN", "")
OUTPUT_FILE   = os.getenv("SURICATA_OUTPUT", "/etc/suricata/rules/cti-iocs.rules")
SURICATA_RELOAD_CMD = "suricatasc -c reload-rules"

# Starting SID for dynamically generated rules
DYNAMIC_SID_START = 9200000


def get_active_indicators() -> list[dict]:
    """
    Pull active, high-confidence CTI indicators from OpenCTI.
    Filters: score >= 60 (high confidence), valid_from <= now.
    """
    if not OPENCTI_TOKEN:
        log.error("OPENCTI_TOKEN not set")
        return []

    query = """
    query GetIndicators($filters: FilterGroup) {
        indicators(filters: $filters, first: 1000) {
            edges {
                node {
                    id
                    name
                    pattern
                    pattern_type
                    x_opencti_score
                    description
                    labels { edges { node { value } } }
                    externalReferences { edges { node { url source_name } } }
                }
            }
        }
    }
    """
    variables = {
        "filters": {
            "mode": "and",
            "filters": [
                {"key": "x_opencti_score", "values": ["60"], "operator": "gte"},
                {"key": "pattern_type", "values": ["stix"]},
            ],
            "filterGroups": []
        }
    }

    try:
        resp = requests.post(
            f"{OPENCTI_URL}/graphql",
            json={"query": query, "variables": variables},
            headers={
                "Authorization": f"Bearer {OPENCTI_TOKEN}",
                "Content-Type":  "application/json",
            },
            timeout=30,
        )
        resp.raise_for_status()
        edges = resp.json().get("data", {}).get("indicators", {}).get("edges", [])
        return [e["node"] for e in edges]
    except Exception as exc:
        log.error("OpenCTI query failed: %s", exc)
        return []


def stix_pattern_to_suricata(indicator: dict, sid: int) -> str | None:
    """
    Convert a STIX 2.1 indicator pattern to a Suricata rule.
    Supports: IPv4, domain, URL, file hash patterns.

    Returns a valid Suricata rule string, or None if conversion fails.
    """
    pattern = indicator.get("pattern", "")
    name    = indicator.get("name", "CTI-Match").replace('"', "'")
    score   = indicator.get("x_opencti_score", 0)
    ioc_id  = indicator.get("id", "unknown")[:8]

    # Derive reference
    refs = indicator.get("externalReferences", {}).get("edges", [])
    ref_str = ""
    if refs:
        ref_url = refs[0].get("node", {}).get("url", "")
        if ref_url:
            ref_str = f'reference:url,{ref_url.replace(",", "")};'

    base_meta = (
        f'metadata:confidence {score}, source OpenCTI, ioc_id {ioc_id};'
        f'{ref_str}'
    )

    # ── IPv4 address pattern ──────────────────────────────────
    m = re.search(r"ipv4-addr:value\s*=\s*'([^']+)'", pattern)
    if m:
        ip = m.group(1)
        # Block traffic to/from this IP on any port
        rule = (
            f'alert ip $HOME_NETS any -> {ip} any '
            f'(msg:"UAV CTI IoC Match - Malicious IP: {ip}"; '
            f'classtype:trojan-activity; {base_meta} '
            f'sid:{sid}; rev:1;)'
        )
        return rule

    # ── Domain pattern ────────────────────────────────────────
    m = re.search(r"domain-name:value\s*=\s*'([^']+)'", pattern)
    if m:
        domain = m.group(1)
        rule = (
            f'alert dns $HOME_NETS any -> any 53 '
            f'(msg:"UAV CTI IoC Match - Malicious Domain: {domain}"; '
            f'dns.query; content:"{domain}"; nocase; '
            f'classtype:trojan-activity; {base_meta} '
            f'sid:{sid}; rev:1;)'
        )
        return rule

    # ── URL pattern ───────────────────────────────────────────
    m = re.search(r"url:value\s*=\s*'([^']+)'", pattern)
    if m:
        url   = m.group(1)
        # Extract path component for content match
        path  = "/" + "/".join(url.split("/")[3:]) if "/" in url[8:] else "/"
        rule  = (
            f'alert http $HOME_NETS any -> any any '
            f'(msg:"UAV CTI IoC Match - Malicious URL: {url[:60]}"; '
            f'http.uri; content:"{path[:50]}"; nocase; '
            f'classtype:trojan-activity; {base_meta} '
            f'sid:{sid}; rev:1;)'
        )
        return rule

    # ── File hash (SHA256) ────────────────────────────────────
    m = re.search(r"file:hashes\.'SHA-256'\s*=\s*'([a-fA-F0-9]{64})'", pattern)
    if m:
        sha256 = m.group(1).lower()
        # Suricata can match file hashes in HTTP transfers
        rule = (
            f'alert http any any -> any any '
            f'(msg:"UAV CTI IoC Match - Malicious File Hash SHA256"; '
            f'filemd5:!{sha256}; '
            f'classtype:malware; {base_meta} '
            f'sid:{sid}; rev:1;)'
        )
        return rule

    log.debug("No conversion for pattern: %s", pattern[:80])
    return None


def write_rules_file(rules: list[str], output: str) -> None:
    """Write generated rules to the Suricata rules file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    header = f"""# =============================================================
# UAV CTI Lab — Dynamically Generated CTI IoC Rules
# Generated: {timestamp}
# Source:    OpenCTI (STIX 2.1 indicators)
# Citation:  OASIS (2021) STIX 2.1 Standard [11]
#
# These rules are auto-refreshed from the CTI platform.
# DO NOT edit manually — changes will be overwritten.
# =============================================================

"""
    with open(output, "w") as f:
        f.write(header)
        for rule in rules:
            f.write(rule + "\n")
    log.info("Wrote %d rules to %s", len(rules), output)


def reload_suricata() -> None:
    """Signal Suricata to hot-reload rules without restart."""
    import subprocess
    try:
        result = subprocess.run(
            SURICATA_RELOAD_CMD.split(),
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            log.info("Suricata rules reloaded successfully")
        else:
            log.warning("Suricata reload returned %d: %s",
                        result.returncode, result.stderr.strip())
    except FileNotFoundError:
        log.warning("suricatasc not found — manual reload required")
    except Exception as exc:
        log.warning("Suricata reload error: %s", exc)


def main() -> None:
    log.info("=== CTI → Suricata Rule Export ===")

    indicators = get_active_indicators()
    log.info("Fetched %d indicators from OpenCTI", len(indicators))

    rules = []
    sid   = DYNAMIC_SID_START
    for ind in indicators:
        rule = stix_pattern_to_suricata(ind, sid)
        if rule:
            rules.append(rule)
            sid += 1

    log.info("Converted %d indicators to Suricata rules", len(rules))

    if rules:
        write_rules_file(rules, OUTPUT_FILE)
        reload_suricata()
    else:
        log.warning("No rules generated — check OpenCTI connectivity and indicator quality")

    log.info("=== Export complete ===")


if __name__ == "__main__":
    main()
