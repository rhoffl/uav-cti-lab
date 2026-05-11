#!/usr/bin/env python3
"""
UAV CTI Lab — MAVLink Intrusion Detection System
File: scripts/detection/mavlink_ids.py

DEFENSIVE PURPOSE ONLY:
Monitors MAVLink telemetry streams for anomalous messages and correlates
detections against CTI indicators from OpenCTI / MISP.

Citations:
  [6]  Rodday et al. (2016) "Exploring Security Vulnerabilities of UAVs."
       IEEE NOMS 2016. doi:10.1109/NOMS.2016.7502939
  [10] Strom et al. (2018) "MITRE ATT&CK." MITRE MTR180035.
  [11] OASIS (2021). STIX 2.1 Standard.
"""

import asyncio
import json
import logging
import os
import socket
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Optional

import requests
from pymavlink import mavutil

# ── Configuration ────────────────────────────────────────────────────────────
OPENCTI_URL   = os.getenv("OPENCTI_URL",   "http://cti-platform:8080")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN", "")
ELASTIC_URL   = os.getenv("ELASTIC_URL",   "http://elasticsearch:9200")
ELASTIC_PASS  = os.getenv("ELASTIC_PASSWORD", "")
MAV_HOST      = os.getenv("MAV_LISTEN_HOST", "0.0.0.0")
MAV_PORT      = int(os.getenv("MAV_LISTEN_PORT", "14556"))
LOG_LEVEL     = os.getenv("LOG_LEVEL", "INFO")
ALERT_BACKEND = os.getenv("ALERT_BACKEND", "elasticsearch")   # or "thehive"
THEHIVE_URL   = os.getenv("THEHIVE_URL",   "http://thehive:9000")
THEHIVE_KEY   = os.getenv("THEHIVE_API_KEY", "")

# MAVLink message IDs requiring extra scrutiny [6]
HIGH_RISK_MSG_IDS = {
    11:  "SET_MODE",
    76:  "COMMAND_LONG",
    84:  "SET_POSITION_TARGET_GLOBAL_INT",
    179: "SET_ACTUATOR_CONTROL_TARGET",
    192: "MAV_CMD_DO_SET_HOME",
}

# MITRE ATT&CK for ICS technique mappings [10]
MSG_TO_TECHNIQUE = {
    11:  ("T0836", "Modify Parameter"),
    76:  ("T0855", "Unauthorized Command Message"),
    84:  ("T0856", "Spoof Reporting Message"),
    179: ("T0804", "Block Command Message"),
}

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
log = logging.getLogger("mavlink-ids")


@dataclass
class Alert:
    """Structured alert following STIX Observed Data conventions [11]."""
    timestamp:        str
    alert_type:       str
    severity:         str          # CRITICAL / HIGH / MEDIUM / LOW
    source_ip:        str
    source_port:      int
    msg_id:           int
    msg_name:         str
    sys_id:           int
    comp_id:          int
    mitre_technique:  str = ""
    mitre_tactic:     str = ""
    description:      str = ""
    ioc_matched:      bool = False
    ioc_reference:    str = ""
    raw_payload_hex:  str = ""


class CTIConnector:
    """Pulls UAV-relevant IoCs from OpenCTI using the REST API."""

    def __init__(self):
        self.headers = {
            "Authorization": f"Bearer {OPENCTI_TOKEN}",
            "Content-Type":  "application/json",
        }
        self.ioc_cache: set = set()
        self.last_refresh = 0
        self.refresh_interval = 300   # 5 minutes

    def refresh_iocs(self) -> None:
        """Pull current IoC indicators from OpenCTI."""
        if time.time() - self.last_refresh < self.refresh_interval:
            return
        try:
            query = {
                "query": """
                    query {
                        indicators(
                            filters: {mode: and, filters: [
                                {key: "x_opencti_score", values: ["50"], operator: gte}
                            ]}
                            first: 500
                        ) {
                            edges {
                                node {
                                    id
                                    pattern
                                    x_opencti_score
                                    name
                                }
                            }
                        }
                    }
                """
            }
            resp = requests.post(
                f"{OPENCTI_URL}/graphql",
                json=query,
                headers=self.headers,
                timeout=10,
            )
            if resp.ok:
                data = resp.json()
                edges = data.get("data", {}).get("indicators", {}).get("edges", [])
                new_iocs = set()
                for edge in edges:
                    pattern = edge.get("node", {}).get("pattern", "")
                    # Extract IP values from STIX patterns like [ipv4-addr:value = '1.2.3.4']
                    if "ipv4-addr:value" in pattern:
                        ip = pattern.split("'")[1] if "'" in pattern else ""
                        if ip:
                            new_iocs.add(ip)
                self.ioc_cache = new_iocs
                self.last_refresh = time.time()
                log.info("CTI refresh: %d IoCs loaded from OpenCTI", len(self.ioc_cache))
        except Exception as exc:
            log.warning("CTI refresh failed: %s", exc)

    def check_ip(self, ip: str) -> bool:
        """Check if an IP matches a known IoC."""
        self.refresh_iocs()
        return ip in self.ioc_cache


class AlertSender:
    """Sends structured alerts to Elasticsearch or TheHive."""

    def send_to_elasticsearch(self, alert: Alert) -> None:
        try:
            index  = f"uav-cti-mavlink-ids-{datetime.now().strftime('%Y.%m.%d')}"
            doc_id = f"{alert.source_ip}-{alert.msg_id}-{int(time.time())}"
            url    = f"{ELASTIC_URL}/{index}/_doc/{doc_id}"
            resp   = requests.put(
                url,
                json=asdict(alert),
                auth=("elastic", ELASTIC_PASS),
                timeout=5,
            )
            if not resp.ok:
                log.warning("Elasticsearch ingest failed: %s", resp.text[:200])
        except Exception as exc:
            log.warning("Elasticsearch send error: %s", exc)

    def send_to_thehive(self, alert: Alert) -> None:
        """Create a TheHive alert case for high/critical detections."""
        if alert.severity not in ("HIGH", "CRITICAL"):
            return
        try:
            case = {
                "title":       f"[UAV-IDS] {alert.alert_type}: {alert.msg_name}",
                "description": (
                    f"MAVLink IDS detected anomalous activity.\n\n"
                    f"**Alert type:** {alert.alert_type}\n"
                    f"**Source:** {alert.source_ip}:{alert.source_port}\n"
                    f"**Message:** {alert.msg_name} (ID {alert.msg_id})\n"
                    f"**System ID:** {alert.sys_id} / Component: {alert.comp_id}\n"
                    f"**MITRE:** {alert.mitre_tactic} / {alert.mitre_technique}\n"
                    f"**IoC match:** {alert.ioc_matched} — {alert.ioc_reference}\n"
                    f"**Timestamp:** {alert.timestamp}"
                ),
                "severity":   3 if alert.severity == "CRITICAL" else 2,
                "source":     "MAVLink-IDS",
                "sourceRef":  f"mavids-{int(time.time())}",
                "type":       "UAV-Intrusion",
                "tags":       ["uav-cti", "mavlink", "auto-detection"],
            }
            requests.post(
                f"{THEHIVE_URL}/api/alert",
                json=case,
                headers={"Authorization": f"Bearer {THEHIVE_KEY}"},
                timeout=5,
            )
        except Exception as exc:
            log.warning("TheHive alert failed: %s", exc)

    def send(self, alert: Alert) -> None:
        log.warning(
            "ALERT [%s] %s | src=%s msg=%s sys_id=%d ioc=%s",
            alert.severity, alert.alert_type,
            alert.source_ip, alert.msg_name,
            alert.sys_id, alert.ioc_matched,
        )
        self.send_to_elasticsearch(alert)
        if ALERT_BACKEND == "thehive":
            self.send_to_thehive(alert)


class MAVLinkIDS:
    """
    CTI-informed intrusion detection system for MAVLink protocol streams.

    Detection logic implements findings from:
      - Rodday et al. (2016) [6]: MAVLink lacks authentication
      - Birnbaum et al. (2016) [7]: anomaly detection in UAV subsystems
    """

    def __init__(self):
        self.cti     = CTIConnector()
        self.sender  = AlertSender()
        # Per-sysid sequence number tracking for injection detection
        self.seq_tracker: dict[int, deque] = defaultdict(lambda: deque(maxlen=50))
        # Rate tracking for flood detection
        self.msg_rates:   dict[tuple, deque] = defaultdict(lambda: deque(maxlen=200))
        # Known authorized GCS system IDs (loaded from env / config)
        self.authorized_sys_ids: set[int] = {
            int(x) for x in os.getenv("AUTHORIZED_SYS_IDS", "255").split(",") if x
        }
        log.info("MAVLink IDS initialized | listen=%s:%d", MAV_HOST, MAV_PORT)

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def check_msg_rate(self, src_ip: str, msg_id: int, window: float = 5.0) -> int:
        """Return count of this (src,msg_id) in the past `window` seconds."""
        key = (src_ip, msg_id)
        now = time.monotonic()
        q   = self.msg_rates[key]
        q.append(now)
        # Remove entries outside window
        while q and q[0] < now - window:
            q.popleft()
        return len(q)

    def check_seq_gap(self, sys_id: int, seq: int) -> Optional[int]:
        """Detect sequence number gaps suggesting injection or replay."""
        q = self.seq_tracker[sys_id]
        if q:
            last = q[-1]
            expected = (last + 1) % 256
            if seq != expected:
                gap = (seq - last) % 256
                if gap > 3:        # Allow small natural gaps
                    return gap
        q.append(seq)
        return None

    def analyze(self, msg, src_ip: str, src_port: int) -> Optional[Alert]:
        """
        Analyze a MAVLink message and return an Alert if suspicious.
        Returns None for benign messages.
        """
        msg_type = msg.get_type()
        if msg_type == "BAD_DATA":
            return None

        # Get message numeric ID
        msg_id   = msg.id if hasattr(msg, "id") else 0
        sys_id   = msg.get_srcSystem()
        comp_id  = msg.get_srcComponent()
        seq      = msg.get_seq()

        # ── Check 1: IoC match on source IP ────────────────────────
        if self.cti.check_ip(src_ip):
            technique, tac_name = MSG_TO_TECHNIQUE.get(msg_id, ("", ""))
            return Alert(
                timestamp       = self._now(),
                alert_type      = "CTI_IOC_MATCH",
                severity        = "CRITICAL",
                source_ip       = src_ip,
                source_port     = src_port,
                msg_id          = msg_id,
                msg_name        = msg_type,
                sys_id          = sys_id,
                comp_id         = comp_id,
                mitre_technique = technique,
                mitre_tactic    = tac_name,
                description     = f"Source IP {src_ip} matches CTI IoC indicator",
                ioc_matched     = True,
                ioc_reference   = f"OpenCTI:{src_ip}",
            )

        # ── Check 2: Unauthorized high-risk command ─────────────────
        if msg_id in HIGH_RISK_MSG_IDS:
            if sys_id not in self.authorized_sys_ids:
                technique, tac_name = MSG_TO_TECHNIQUE.get(msg_id, ("", ""))
                return Alert(
                    timestamp       = self._now(),
                    alert_type      = "UNAUTHORIZED_COMMAND",
                    severity        = "HIGH",
                    source_ip       = src_ip,
                    source_port     = src_port,
                    msg_id          = msg_id,
                    msg_name        = HIGH_RISK_MSG_IDS[msg_id],
                    sys_id          = sys_id,
                    comp_id         = comp_id,
                    mitre_technique = technique,
                    mitre_tactic    = tac_name,
                    description     = (
                        f"High-risk MAVLink command {HIGH_RISK_MSG_IDS[msg_id]} "
                        f"from unauthorized sys_id={sys_id} ({src_ip})"
                    ),
                )

        # ── Check 3: Heartbeat flood (DoS precursor) ────────────────
        if msg_type == "HEARTBEAT":
            rate = self.check_msg_rate(src_ip, msg_id, window=10.0)
            if rate > 100:
                return Alert(
                    timestamp   = self._now(),
                    alert_type  = "HEARTBEAT_FLOOD",
                    severity    = "MEDIUM",
                    source_ip   = src_ip,
                    source_port = src_port,
                    msg_id      = msg_id,
                    msg_name    = "HEARTBEAT",
                    sys_id      = sys_id,
                    comp_id     = comp_id,
                    description = f"Heartbeat flood: {rate} msgs/10s from {src_ip}",
                )

        # ── Check 4: Sequence number gap (injection indicator) ───────
        gap = self.check_seq_gap(sys_id, seq)
        if gap is not None:
            return Alert(
                timestamp   = self._now(),
                alert_type  = "SEQ_GAP",
                severity    = "MEDIUM",
                source_ip   = src_ip,
                source_port = src_port,
                msg_id      = msg_id,
                msg_name    = msg_type,
                sys_id      = sys_id,
                comp_id     = comp_id,
                description = (
                    f"MAVLink sequence gap={gap} from sys_id={sys_id}. "
                    "Possible packet injection or replay."
                ),
            )

        return None   # No anomaly detected

    def run(self) -> None:
        """Start monitoring the MAVLink UDP stream."""
        mav_uri = f"udpin:{MAV_HOST}:{MAV_PORT}"
        log.info("Connecting to MAVLink stream: %s", mav_uri)
        mav = mavutil.mavlink_connection(mav_uri)
        log.info("MAVLink IDS active — waiting for messages...")

        while True:
            try:
                msg = mav.recv_match(blocking=True, timeout=2.0)
                if msg is None:
                    continue

                # Extract source address from the underlying socket
                src_ip   = getattr(mav, "address", ("0.0.0.0", 0))[0]
                src_port = getattr(mav, "address", ("0.0.0.0", 0))[1]

                alert = self.analyze(msg, src_ip, src_port)
                if alert:
                    self.sender.send(alert)

            except KeyboardInterrupt:
                log.info("MAVLink IDS shutting down.")
                break
            except Exception as exc:
                log.error("IDS loop error: %s", exc)
                time.sleep(1)


if __name__ == "__main__":
    ids = MAVLinkIDS()
    ids.run()
