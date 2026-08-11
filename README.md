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

## Troubleshooting

This section documents the two major issues that blocked the automation from working, and how each was diagnosed and resolved. Both failures were silent — the pipeline appeared to run (trigger history recorded executions, alerts fired) without any obvious error pointing to the actual cause.

### 7.1 Automatic IP Blocking Wasn't Firing

**Symptom:**
The Splunk alert triggered correctly, and trigger history confirmed executions — but the pfSense firewall rule was never created. No errors appeared in the alert action's own log.

**Root Cause #1 — Invalid configuration key:**
Checking the Splunk startup log revealed the actual problem, which had been silently breaking the app since it was built:

`script` is not a valid key for a modular alert action (`is_custom = 1`). The correct key is `alert.execute.cmd`. Because Splunk silently rejected the invalid line at startup, the alert action was never properly registered, even though the app appeared to load fine (`splunk display app pfsense_blocker` returned successfully).

**Fix:**
```ini
# Before (invalid)
script = alert_actions.py

# After (correct)
alert.execute.cmd = alert_actions.py
```

**Root Cause #2 — Legacy vs. JSON payload mismatch:**
With the config key fixed, the action still didn't execute correctly. `alert_actions.conf` specified `payload_format = json`, which tells Splunk to pass alert data as a JSON blob on stdin. However, `alert_actions.py` was originally written for the legacy "Run a Script" convention, reading results via the `SPLUNK_ARG_8` environment variable — which is only populated when `is_custom = 0`. With `is_custom = 1` and `payload_format = json` set, that environment variable was never populated, so the script silently read `None` and exited without doing anything.

**Fix:**
Rewrote `alert_actions.py` to read the JSON payload from stdin, and to correctly decompress the gzipped CSV results file (modular alert results are gzip-compressed, unlike the legacy plain-text results file):

```python
payload = json.loads(sys.stdin.read())
results_file = payload.get("results_file")

with gzip.open(results_file, "rt") as f:
    reader = csv.DictReader(f)
    for row in reader:
        ip = row.get("attacker_ip")
        ...
```

**Verification:**
After both fixes, restarting Splunk and re-triggering the alert produced this in `alert_action.log`:

`script` is not a valid key for a modular alert action (`is_custom = 1`). The correct key is `alert.execute.cmd`. Because Splunk silently rejected the invalid line at startup, the alert action was never properly registered, even though the app appeared to load fine (`splunk display app pfsense_blocker` returned successfully).

**Fix:**
```ini
# Before (invalid)
script = alert_actions.py

# After (correct)
alert.execute.cmd = alert_actions.py
```

**Root Cause #2 — Legacy vs. JSON payload mismatch:**
With the config key fixed, the action still didn't execute correctly. `alert_actions.conf` specified `payload_format = json`, which tells Splunk to pass alert data as a JSON blob on stdin. However, `alert_actions.py` was originally written for the legacy "Run a Script" convention, reading results via the `SPLUNK_ARG_8` environment variable — which is only populated when `is_custom = 0`. With `is_custom = 1` and `payload_format = json` set, that environment variable was never populated, so the script silently read `None` and exited without doing anything.

**Fix:**
Rewrote `alert_actions.py` to read the JSON payload from stdin, and to correctly decompress the gzipped CSV results file (modular alert results are gzip-compressed, unlike the legacy plain-text results file):

```python
payload = json.loads(sys.stdin.read())
results_file = payload.get("results_file")

with gzip.open(results_file, "rt") as f:
    reader = csv.DictReader(f)
    for row in reader:
        ip = row.get("attacker_ip")
        ...
```

**Verification:**
After both fixes, restarting Splunk and re-triggering the alert produced this in `alert_action.log`:

confirming the script correctly parsed the alert results and passed the attacker's IP through to `block_ip.py`.

<img width="3827" height="1997" alt="image" src="https://github.com/user-attachments/assets/26b497a7-60c7-438d-aba4-0705757acfee" />

---

### 7.2 Email Notifications Stopped After the First Send

**Symptom:**
The email action fired successfully exactly once, then never sent again on subsequent alert triggers — with no indication in the Splunk UI of why.

**Diagnosis:**
Checking `splunkd.log` revealed the real error:

This pointed to a DNS resolution failure, not a Splunk or SMTP configuration issue. Testing directly on the Splunk server confirmed the server had no working DNS resolution at all:

```bash
$ nslookup smtp.gmail.com
;; Got SERVFAIL reply from 127.0.0.53
** server can't find smtp.gmail.com: SERVFAIL
```

Testing further showed the server couldn't reach *any* external host — not just DNS:

```bash
$ nslookup smtp.gmail.com 8.8.8.8
;; UDP setup with 8.8.8.8#53(8.8.8.8) for smtp.gmail.com failed: network unreachable.
```

Checking the routing table confirmed the actual root cause — there was no default route at all:

```bash
$ ip route
192.168.174.0/24 dev ens33 proto kernel scope link src 192.168.174.10
```

Only the local subnet route existed; nothing pointed traffic anywhere beyond `192.168.174.0/24`. This explained why pfSense API calls (same subnet) worked perfectly while everything requiring internet access (DNS, SMTP) failed silently.

**Root Cause:**
The server's Netplan configuration had a default route defined, but pointing to the wrong gateway IP — a leftover from a different network setup:

```yaml
routes:
    - to: default
      via: 192.168.10.1   # wrong subnet entirely
```

The lab's actual network was `192.168.174.0/24`, with pfSense's LAN interface at `192.168.174.1` — so this route pointed to an address that didn't exist on the network at all, making it dead on arrival.

**Fix:**
```yaml
routes:
    - to: default
      via: 192.168.174.1
```

Applied with:
```bash
sudo netplan apply
```

**Verification:**
```bash
$ ping -c 3 8.8.8.8
64 bytes from 8.8.8.8: icmp_seq=1 ttl=127 time=28.8 ms
...
$ nslookup smtp.gmail.com
Non-authoritative answer:
Name:   smtp.gmail.com
Address: 172.217.76.109
```

Both internet connectivity and DNS resolution were restored, confirmed stable after a full server reboot, and email notifications resumed working on every subsequent alert trigger.

<img width="3807" height="1205" alt="image" src="https://github.com/user-attachments/assets/b3febed1-bff1-446b-b063-c463f7c71f32" />

---

### 7.3 What This Troubleshooting Demonstrated
Both issues shared a common thread: **the failure was silent at the layer where I was looking, and only visible one layer deeper.** The alert action problem required reading Splunk's startup log rather than its runtime log; the email problem required testing DNS and routing directly on the OS rather than assuming it was a Splunk or SMTP credential issue. This reinforced the importance of isolating each layer of a pipeline — application config, script logic, and OS-level networking — independently when diagnosing a failure, rather than assuming the problem lives where the symptom first appears.


## Proof It Works — End-to-End Demo

This section demonstrates the complete automated response pipeline working in a single, connected test: a brute-force attack is launched, Splunk detects and triggers on it, and both automated response actions fire — the attacker's IP is blocked on pfSense and an email notification is delivered — with no manual step in between.

### 8.1 Attack Launched — Crowbar Brute Force
Crowbar was run from the Kali Linux attacker machine (`192.168.41.250`) against the `boma` account on the domain-joined Windows 10 client, using a password list containing the correct credential to guarantee a mix of failed and successful login attempts.

<img width="3817" height="1350" alt="image" src="https://github.com/user-attachments/assets/ef936ec5-790d-4288-93b5-a23e55333112" />

### 8.2 Detection — Splunk Triggered Alert
The brute-force pattern (≥3 failed logons, Event ID 4625, within a 5-minute window) was detected by the scheduled Splunk search, and the alert fired. Splunk's **Activity → Triggered Alerts** confirms the alert triggered, with both configured actions (email and `pfsense_block`) shown as executed.

<img width="3815" height="1230" alt="image" src="https://github.com/user-attachments/assets/5da9754b-cd9b-4d2d-8f65-351f26589f2a" />

### 8.3 Automated Response — Attacker IP Blocked on pfSense
The instant the alert fired, `alert_actions.py` extracted the attacker's IP from the search results and called `block_ip.py`, which authenticated to the pfSense REST API and created a new firewall rule blocking `192.168.41.250` — automatically, with no manual firewall configuration.

<img width="3835" height="1905" alt="image" src="https://github.com/user-attachments/assets/3e5cc796-5b4d-47ca-87ad-0f94c4b306f4" />

### 8.4 Automated Response — Email Notification Delivered
At the same time, Splunk's email action sent a notification to the admin inbox, confirming the brute-force attack had been detected and responded to.

<img width="576" height="1280" alt="WhatsApp Image 2026-08-11 at 05 05 17" src="https://github.com/user-attachments/assets/07c430d7-f2b4-49c2-bb4f-5f0f9e5a6c2d" />

### 8.5 Result
A single brute-force attempt against the domain was detected, the admin was notified by email, and the attacker's IP was blocked on the firewall all within seconds of the attack pattern being logged, with zero manual intervention at any stage of the response.

### 9 Key Takeaways
- Modular Splunk alert actions have strict, non-obvious configuration requirements — `alert.execute.cmd` vs. `script`, and JSON vs. legacy payload formats are easy to get wrong and fail silently rather than throwing a clear error
- A "working" automation pipeline can fail at any layer — application config, script logic, or OS-level networking — and each layer requires a different diagnostic approach; assuming the problem is where the symptom appears can send you looking in the wrong place entirely
- Reading Splunk's startup log (not just the runtime/action log) was the key to finding the actual root cause of the alert action failure — a reminder that the first log you check isn't always the right one
- Automating response, not just detection, is what turns a SOC lab into something closer to real defensive tooling — detection alone tells you something happened; automated response actually does something about it
- Basic infrastructure fundamentals (routing tables, default gateways, DNS resolution chains) matter just as much as the security tooling itself — the email failure had nothing to do with Splunk or SMTP credentials, it was a single wrong IP in a network config file
