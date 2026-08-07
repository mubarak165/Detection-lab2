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
