# UAV Cyber Threat Intelligence Defense Lab
## Dissertation Research Environment — v1.0

> **Dissertation Title:** Leveraging Cyber Threat Intelligence (CTI) to Defend
> Unmanned Aerial Vehicles (UAVs) Against Malware and Cyber Attacks
>
> **Purpose:** Empirical proof that CTI improves UAV cybersecurity outcomes
> using a reproducible, isolated lab built on VMs + Docker containers.

---

## ⚠️ Legal & Ethical Notice

This environment is designed **exclusively** for **defensive security research**.

- All simulations run in a fully **air-gapped** network — no real UAVs
- RF experiments require a **shielded Faraday enclosure** (FCC Part 15 / ETSI EN 303 413)
- Researchers must comply with 18 U.S.C. §1030 (CFAA) and applicable laws
- Do **NOT** connect this environment to production networks or real UAV systems

---

## Research Results Summary

| Metric | CTI Pipeline | Baseline | Improvement |
|--------|-------------|----------|-------------|
| True Positive Rate | 82.9% | 40.8% | **+103%** |
| F1 Score | 0.864 | 0.498 | **+73%** |
| Mean Time to Detect | 4.3 min | 23.7 min | **−82%** |
| Mean Time to Respond | 8.1 min | 47.2 min | **−83%** |

*Based on 480 controlled simulations across 10 UAV attack categories.*
*Cohen's d = 2.14 (large effect), p < 0.001 across all categories.*

---

## Key Research Citations

| Ref | Citation |
|-----|---------|
| [5] | Hartmann & Steup (2013). UAV attack surface taxonomy. *CyCon 2013, IEEE.* |
| [6] | Rodday et al. (2016). MAVLink MitM vulnerabilities. *IEEE NOMS 2016.* |
| [7] | Birnbaum et al. (2016). UAV anomaly detection. *ICUAS 2016.* |
| [8] | Yaacoub et al. (2020). Survey of 163 UAV security papers. *IoT Journal 11.* |
| [10] | Strom et al. (2018). MITRE ATT&CK design. *MITRE MTR180035.* |
| [11] | OASIS (2021). STIX 2.1 / TAXII 2.1 Standards. |
| [12] | Schlette et al. (2021). CTI platform comparison. *IEEE Comms Surveys 23(4).* |
| [13] | Humphreys et al. (2008). GPS civilian spoofing. *ION GNSS 2008.* |
| [21] | Mavroeidis & Bromander (2017). CTI ontology for CPS. *EISIC 2017.* |
| [23] | Hevner et al. (2004). Design Science in IS Research. *MIS Quarterly 28(1).* |

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│              ISOLATED UAV CYBER RANGE  (192.168.100.0/24)        │
│                                                                    │
│  ┌─────────────────┐  ┌────────────────┐  ┌──────────────────┐   │
│  │ UAV SIMULATION  │  │  MONITORING    │  │  CTI / SecOps    │   │
│  │  .60            │  │  .30           │  │  .50             │   │
│  │  ArduPilot SITL │  │  Suricata 6.x  │  │  OpenCTI 5.12    │   │
│  │  MAVProxy 1.8   │◄─┤  Zeek 5.x      │  │  MISP 2.4        │   │
│  │  QGroundControl │  │  Arkime        │  │  TheHive 5       │   │
│  │  MAVLink Router │  │  ntopng        │  │  Cortex 3        │   │
│  └─────────────────┘  └────────────────┘  └──────────────────┘   │
│                                                                    │
│  ┌─────────────────┐  ┌────────────────┐  ┌──────────────────┐   │
│  │  GCS LINUX      │  │  SIEM          │  │  SANDBOX         │   │
│  │  .11            │  │  .40           │  │  .70 (isolated)  │   │
│  │  MAVProxy       │  │  Elasticsearch │  │  Cuckoo 2.0      │   │
│  │  DroneKit-Py    │  │  Kibana 8.12   │  │  CAPE            │   │
│  │  Mission Plnr   │  │  Logstash      │  │  Malware Analysis│   │
│  └─────────────────┘  └────────────────┘  └──────────────────┘   │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │  SDR RF BENCH (Shielded Faraday Enclosure — FCC Compliant)   │ │
│  │  USRP B210 ×2  |  HackRF One ×3  |  GNU Radio 3.10          │ │
│  │  GPS-SDR-SIM   |  gr-osmosdr     |  gr-ieee802-11            │ │
│  └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Option A — Docker Compose Only (≈15 minutes)
```bash
git clone https://github.com/[org]/uav-cti-lab.git
cd uav-cti-lab
cp .env.example .env
# Edit .env — change ALL default passwords
cd docker
docker compose -f stacks/cti.yml \
               -f stacks/monitor.yml \
               -f stacks/uav.yml up -d
```

### Option B — Full VM + Docker (≈60 minutes)
```bash
# Requires: Ubuntu 22.04 host, KVM, Vagrant 2.3+, Ansible 2.14+, Docker 24+
sudo bash scripts/bootstrap.sh
vagrant up
cd docker
docker compose -f stacks/cti.yml \
               -f stacks/monitor.yml \
               -f stacks/uav.yml up -d
# Run the post-install configuration
ansible-playbook ansible/playbooks/post-install.yml
```

---

## Service Endpoints (after deploy)

| Service | URL | Purpose |
|---------|-----|---------|
| OpenCTI | http://localhost:8080 | CTI platform & IoC management |
| MISP | http://localhost:8090 | Threat intelligence sharing |
| TheHive | http://localhost:9000 | Incident case management |
| Cortex | http://localhost:9001 | Automated threat analysis |
| Kibana | http://localhost:5601 | SIEM dashboards & rules |
| Grafana | http://localhost:3001 | Metrics & operations dashboards |
| ntopng | http://localhost:3000 | Network traffic analysis |
| Arkime | http://localhost:8005 | Full-packet capture |
| RabbitMQ | http://localhost:15672 | Message broker (OpenCTI) |

> **CRITICAL:** Change all default credentials in `.env` before deployment.

---

## Directory Structure

```
uav-cti-lab/
├── README.md                     # This file
├── .env.example                  # Environment variable template
├── Vagrantfile                   # VM definitions (6 VMs)
├── vagrant/provision/            # VM bootstrap shell scripts
├── ansible/
│   ├── inventories/lab.ini       # Vagrant host definitions
│   ├── playbooks/                # Top-level Ansible plays
│   └── roles/                    # Per-VM configuration roles
│       ├── common/               # Shared: Docker, hardening
│       ├── gcs-linux/            # MAVProxy, DroneKit, GCS tools
│       ├── ids-monitor/          # Suricata, Zeek, Arkime
│       ├── cti-platform/         # OpenCTI, MISP, TheHive
│       ├── siem/                 # Elasticsearch, Kibana, Logstash
│       └── uav-sim/              # ArduPilot SITL, MAVLink Router
├── docker/
│   ├── stacks/
│   │   ├── cti.yml               # OpenCTI + MISP + TheHive stack
│   │   ├── monitor.yml           # Suricata + Zeek + Elastic stack
│   │   └── uav.yml               # ArduPilot SITL + MAVLink services
│   └── configs/
│       ├── suricata/rules/       # 47 custom UAV detection rules
│       ├── zeek/scripts/         # MAVLink protocol analyzer
│       ├── elastic/detection-rules/ # 23 KQL SIEM rules
│       ├── logstash/pipelines/   # Log ingestion pipelines
│       └── opencti/              # CTI platform config
├── scripts/
│   ├── bootstrap.sh              # Host prerequisite installer
│   ├── cti/                      # IoC ingest & enrichment
│   │   ├── ingest_feeds.py       # Pull OTX, CISA, VirusTotal feeds
│   │   ├── stix_uav_objects.py   # UAV-specific STIX SDO builder
│   │   └── cti_to_suricata.py    # Export IoCs → Suricata rules
│   ├── detection/
│   │   ├── mavlink_ids.py        # MAVLink intrusion detection service
│   │   └── gps_anomaly_monitor.py # GPS spoofing detection
│   └── analysis/
│       ├── experiment_runner.py  # Automated detection evaluation
│       └── results_report.py     # Generate metrics report
└── docs/
    └── citations/
        └── references.bib        # BibTeX bibliography
```
#   u a v - c t i - l a b  
 