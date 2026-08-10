# Automated Incident Response: Splunk + pfSense Integration for Brute-Force Detection

## Title & Summary
- Project name: Automated Incident Response: Splunk + pfSense Integration for Brute-Force Detection
- Summary: This project builds on my earlier [Home SOC Lab](https://github.com/mubarak165/Detection-lab) by taking the existing brute-force detection pipeline and turning it into a fully automated response system. I integrated a pfSense firewall into the lab topology and built a custom Splunk app (`pfsense_blocker`) that triggers two actions the moment a brute-force alert fires: an email notification to the admin, and an automatic firewall rule on pfSense that blocks the attacker's IP via its REST API. Getting there wasn't straightforward — I had to debug a silently-failing Splunk modular alert action down to a single invalid configuration key, and separately trace a broken email notification all the way down to a misconfigured default gateway in the server's network config. The end result is a closed-loop system: a brute-force attack is detected, the admin is notified, and the attacker is blocked, all without manual intervention.

## Objectives
- Extend the existing brute-force detection pipeline (Splunk alert on Event ID 4625) with automated response actions instead of manual/alert-only handling
- Integrate pfSense as the lab's firewall/gateway and expose its REST API for programmatic firewall rule creation
- Build a custom Splunk app that fires two actions simultaneously from a single alert: email notification and automatic IP blocking
- Validate the full pipeline end-to-end — attack simulated, detected, and automatically responded to, with no manual steps
- Troubleshoot real infrastructure issues as they came up — a misconfigured modular alert action, a legacy vs. JSON payload mismatch, and a broken default route causing silent email failures — rather than following a scripted walkthrough
  
## Methodology Note
Scripts and configuration were developed iteratively with AI assistance (Claude) for drafting and debugging; all infrastructure setup, testing, and troubleshooting were performed hands-on in the lab.

## Relationship to Base Lab
This project builds directly on top of my earlier [Home SOC Lab: AD + Sysmon + Splunk Detection Pipeline](https://github.com/mubarak165/Detection-lab). The Active Directory domain, Sysmon telemetry, Splunk Universal Forwarder setup, and the brute-force detection alert (Event ID 4625) were all built and validated in that project and are not re-documented here. This project picks up right after detection was already working, and focuses entirely on turning that detection into an automated response.

## What's New in This Project
- pfSense added to the lab topology as the firewall/gateway, with REST API access enabled for programmatic rule creation
- Custom Splunk app (`pfsense_blocker`) built to automate incident response
- Two actions now fire simultaneously the moment the existing brute-force alert triggers:
  - **Email notification** sent to the admin
  - **Automatic firewall rule** created on pfSense to block the attacker's IP
    
## Architecture / Lab Environment
This project extends the base lab by adding a pfSense firewall as the network gateway, splitting the environment into segmented VMnets, and integrating pfSense's REST API with Splunk to enable automated attacker IP blocking.

<img width="600" height="453" alt="firewall project " src="https://github.com/user-attachments/assets/0a764150-f710-4e31-aa2c-864bb89f2646" />

**Network Setup:**
- Network: `192.168.174.0/24`
- Splunk server: `192.168.174.10`
- pfSense (firewall/gateway): `192.168.174.1`
- Windows 10 client: VMnet1 (LAN segment)
- Attacker machine (Kali): VMnet2 (isolated LAN segment)

**Tools used:**
- pfSense (firewall, REST API for automated rule creation)
- Splunk Enterprise (indexer, custom alert action app: `pfsense_blocker`)
- Windows 10 (domain-joined client, target of brute-force attack)
- Kali Linux + Crowbar (attack simulation)
- Python 3 (custom alert action scripts: `alert_actions.py`, `block_ip.py`)

## Build Process — Automated Response Pipeline

### 6.1 pfSense Setup (LAN/WAN Config, REST API Access)
pfSense was deployed as the firewall/gateway for the lab, sitting between the router/internet connection and two segmented internal networks (VMnet1 for the Splunk server and Windows client, VMnet2 for the isolated attacker machine).

- Configured the **WAN interface** to receive the upstream connection from the router
- Configured the **LAN interface** (`192.168.174.1`) to serve as the default gateway for both internal VMnets
- Enabled the **pfSense REST API** package to allow programmatic firewall rule creation from external scripts
- Generated an API key/credentials to authenticate requests from the Splunk server to pfSense
- Verified manually that a firewall block rule could be created via a direct API call before wiring it into any automation

**PFSENSE INTERFACE**
<img width="3810" height="1945" alt="image" src="https://github.com/user-attachments/assets/88687ce1-d2c1-49bd-bb31-d66d34cfa4a3" />

**REST API**
<img width="3805" height="2017" alt="image" src="https://github.com/user-attachments/assets/db171cdd-c972-4711-a29c-3b4a880190c1" />

### 6.2 Custom Splunk App Structure (`pfsense_blocker`)
Built a custom Splunk app to house the automated response logic, following Splunk's standard app directory structure:

<img width="3807" height="1365" alt="image" src="https://github.com/user-attachments/assets/4a85c5c1-071d-4817-87d0-67b23a1e1674" />


**`alert_actions.conf`** — registers the custom alert action with Splunk. This is a modular alert action (`is_custom = 1`), meaning Splunk invokes it via `alert.execute.cmd` and passes results as a JSON payload on stdin rather than the legacy `SPLUNK_ARG_*` environment variable convention:

```ini
[pfsense_block]
is_custom = 1
label = Block IP in pfSense
description = Blocks attacking IP on pfSense
python.version = python3
alert.execute.cmd = alert_actions.py
payload_format = json
```

**`alert_actions.py`** — receives the JSON payload from Splunk on stdin, decompresses and parses the gzipped CSV results file, extracts the `attacker_ip` field, and calls `block_ip.py` for each match:

```python
#!/usr/bin/env python3
import sys
import json
import gzip
import csv
import subprocess
import logging

logging.basicConfig(
    filename="/opt/splunk/etc/apps/pfsense_blocker/bin/alert_action.log",
    level=logging.DEBUG,
    format="%(asctime)s %(message)s"
)

def main():
    payload = json.loads(sys.stdin.read())
    logging.debug("Payload received: %s", payload)

    results_file = payload.get("results_file")
    if not results_file:
        logging.error("No results_file in payload")
        return 1

    with gzip.open(results_file, "rt") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip = row.get("attacker_ip")
            if ip:
                logging.debug("Blocking IP: %s", ip)
                subprocess.run([
                    "python3",
                    "/opt/splunk/etc/apps/pfsense_blocker/bin/block_ip.py",
                    ip
                ])
    return 0

if __name__ == "__main__":
    sys.exit(main())
```

**`block_ip.py`** — takes the attacker's IP as a command-line argument and sends an authenticated POST request to the pfSense REST API, creating a new firewall block rule on the LAN interface for that IP. Authentication is handled via an API key stored in the script (excluded from this repo for security).
