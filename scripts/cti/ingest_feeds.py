#!/usr/bin/env python3
"""
UAV CTI Lab — Threat Intelligence Feed Ingestion
File: scripts/cti/ingest_feeds.py

Pulls UAV-relevant Indicators of Compromise from public threat feeds
and imports them into MISP and OpenCTI for correlation.

Citations:
  [11] OASIS (2021). STIX 2.1 Standard. https://docs.oasis-open.org/cti/stix/v2.1/
  [12] Schlette et al. (2021). "Comparative Study on CTI."
       IEEE Communications Surveys 23(4). doi:10.1109/COMST.2021.3117338
"""

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any

import requests

log = logging.getLogger("cti-ingest")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# ── Configuration ────────────────────────────────────────────────────────────
OPENCTI_URL   = os.getenv("OPENCTI_URL",   "http://localhost:8080")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN", "")
MISP_URL      = os.getenv("MISP_URL",      "http://localhost:8090")
MISP_KEY      = os.getenv("MISP_KEY",      "")
OTX_API_KEY   = os.getenv("OTX_API_KEY",   "")
CISA_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_cisa_ics_advisories() -> list[dict]:
    """
    Fetch CISA ICS-CERT advisories relevant to UAV/embedded systems.
    Returns list of structured vulnerability records.

    Source: CISA Known Exploited Vulnerabilities catalog.
    Ref: CISA (2022) ICS Advisory ICSA-22-131-01: DJI AeroScope.
    """
    log.info("Fetching CISA KEV catalog...")
    try:
        resp = requests.get(CISA_FEED_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])

        # Filter for ICS/embedded/firmware-relevant entries
        keywords = [
            "firmware", "embedded", "iot", "industrial", "scada",
            "uav", "drone", "mavlink", "ardupilot", "dji",
        ]
        relevant = [
            v for v in vulns
            if any(kw in (v.get("product", "") + v.get("vendorProject", "") +
                           v.get("shortDescription", "")).lower()
                   for kw in keywords)
        ]
        log.info("CISA KEV: %d total → %d ICS/UAV-relevant", len(vulns), len(relevant))
        return relevant
    except Exception as exc:
        log.error("CISA fetch failed: %s", exc)
        return []


def fetch_otx_pulses(tag: str = "UAV") -> list[dict]:
    """
    Fetch OTX AlienVault pulses tagged with UAV/ICS/drone keywords.
    Returns list of IoC indicators.

    Source: AlienVault Open Threat Exchange (OTX).
    """
    if not OTX_API_KEY:
        log.info("OTX_API_KEY not set — skipping OTX feed")
        return []

    log.info("Fetching OTX pulses for tag: %s", tag)
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    iocs = []
    try:
        for search_tag in ["UAV", "drone", "MAVLink", "ICS", "SCADA"]:
            url  = f"https://otx.alienvault.com/api/v1/pulses/search?q={search_tag}&limit=50"
            resp = requests.get(url, headers=headers, timeout=30)
            if resp.ok:
                for pulse in resp.json().get("results", []):
                    for indicator in pulse.get("indicators", []):
                        iocs.append({
                            "type":   indicator.get("type"),
                            "value":  indicator.get("indicator"),
                            "source": f"OTX-{pulse.get('name', 'unknown')}",
                            "tlp":    "WHITE",
                        })
        log.info("OTX: collected %d indicators", len(iocs))
    except Exception as exc:
        log.error("OTX fetch failed: %s", exc)
    return iocs


def build_stix_indicator(ioc: dict) -> dict:
    """
    Convert a raw IoC dict to a STIX 2.1 Indicator object.

    Ref [11]: OASIS STIX 2.1 — Indicator SDO.
    """
    ioc_type  = ioc.get("type", "").lower()
    ioc_value = ioc.get("value", "")

    # Map OTX/CISA types to STIX patterns
    if ioc_type in ("ipv4", "ip", "IPv4"):
        pattern = f"[ipv4-addr:value = '{ioc_value}']"
    elif ioc_type in ("domain", "hostname"):
        pattern = f"[domain-name:value = '{ioc_value}']"
    elif ioc_type in ("url", "URL"):
        pattern = f"[url:value = '{ioc_value}']"
    elif ioc_type in ("md5", "sha1", "sha256", "FileHash-SHA256"):
        hash_type = ioc_type.upper().replace("FILEHASH-", "")
        pattern = f"[file:hashes.'{hash_type}' = '{ioc_value}']"
    else:
        return {}

    return {
        "type":          "indicator",
        "spec_version":  "2.1",
        "id":            f"indicator--{hash(ioc_value) & 0xFFFFFFFF:08x}-0000-0000-0000-000000000000",
        "created":       datetime.now(timezone.utc).isoformat(),
        "modified":      datetime.now(timezone.utc).isoformat(),
        "name":          f"{ioc.get('source','unknown')}: {ioc_value}",
        "pattern":       pattern,
        "pattern_type":  "stix",
        "valid_from":    datetime.now(timezone.utc).isoformat(),
        "labels":        ["malicious-activity", "uav-threat"],
        "description":   f"IoC from {ioc.get('source','unknown')}. TLP:{ioc.get('tlp','WHITE')}.",
    }


def push_to_opencti(indicators: list[dict]) -> int:
    """
    Push STIX 2.1 indicators to OpenCTI via the STIX2 bundle import API.
    Returns count of successfully pushed indicators.
    """
    if not OPENCTI_TOKEN:
        log.warning("OPENCTI_TOKEN not set — skipping OpenCTI push")
        return 0

    bundle = {
        "type":    "bundle",
        "id":      f"bundle--{int(time.time())}",
        "objects": [ind for ind in indicators if ind],
    }

    try:
        resp = requests.post(
            f"{OPENCTI_URL}/api/import/file/stix",
            json=bundle,
            headers={
                "Authorization": f"Bearer {OPENCTI_TOKEN}",
                "Content-Type":  "application/json",
            },
            timeout=60,
        )
        if resp.ok:
            log.info("OpenCTI import: %d indicators pushed", len(bundle["objects"]))
            return len(bundle["objects"])
        else:
            log.error("OpenCTI push failed: %s — %s", resp.status_code, resp.text[:200])
            return 0
    except Exception as exc:
        log.error("OpenCTI connection error: %s", exc)
        return 0


def push_to_misp(indicators: list[dict]) -> int:
    """
    Push indicators to MISP as a new event.
    Returns count pushed.
    """
    if not MISP_KEY:
        log.warning("MISP_KEY not set — skipping MISP push")
        return 0
    try:
        from pymisp import MISPEvent, MISPAttribute, PyMISP
        misp  = PyMISP(MISP_URL, MISP_KEY, ssl=False)
        event = MISPEvent()
        event.info     = f"UAV CTI Lab Feed Import — {datetime.now().strftime('%Y-%m-%d')}"
        event.distribution = 0    # Your organisation only
        event.threat_level_id = 2
        event.analysis = 1

        count = 0
        for ind in indicators:
            if not ind:
                continue
            pattern = ind.get("pattern", "")
            if "ipv4-addr" in pattern:
                ip = pattern.split("'")[1]
                attr = MISPAttribute()
                attr.type  = "ip-dst"
                attr.value = ip
                attr.comment = ind.get("description", "")
                event.add_attribute(**attr)
                count += 1
            elif "domain-name" in pattern:
                dom = pattern.split("'")[1]
                event.add_attribute("domain", dom, comment=ind.get("description", ""))
                count += 1

        result = misp.add_event(event, pythonify=True)
        log.info("MISP import: event %s created with %d attributes",
                 getattr(result, "id", "?"), count)
        return count
    except Exception as exc:
        log.error("MISP push failed: %s", exc)
        return 0


def main() -> None:
    log.info("=== UAV CTI Feed Ingestion ===")

    # 1. Collect IoCs from configured feeds
    all_iocs: list[dict] = []

    cisa_vulns = fetch_cisa_ics_advisories()
    log.info("CISA: %d relevant vulnerabilities found", len(cisa_vulns))

    otx_iocs = fetch_otx_pulses()
    all_iocs.extend(otx_iocs)

    # 2. Convert to STIX 2.1
    stix_indicators = [build_stix_indicator(ioc) for ioc in all_iocs]
    stix_indicators = [s for s in stix_indicators if s]
    log.info("STIX conversion: %d indicators prepared", len(stix_indicators))

    # 3. Push to platforms
    opencti_count = push_to_opencti(stix_indicators)
    misp_count    = push_to_misp(stix_indicators)

    log.info("=== Ingestion complete: OpenCTI=%d MISP=%d ===", opencti_count, misp_count)


if __name__ == "__main__":
    main()
