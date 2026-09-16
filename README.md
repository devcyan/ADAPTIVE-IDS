# ADAPTIVE-IDS

**ADAPTIVE-IDS** is a Python-based network intrusion detection system designed to monitor live network traffic, identify suspicious activity using rule-based detection, and display security events through a real-time web dashboard.

The project is being developed incrementally, starting with a lightweight rule-based IDS and evolving toward more advanced security monitoring and response capabilities.

---

## Current Version

**v1.0 — Rule-Based Network Intrusion Detection**

The current version focuses on:

* Live packet capture
* Network traffic statistics
* Real-time packet monitoring
* Rule-based intrusion detection
* Security alert generation
* Web-based monitoring dashboard
* Configurable network interface
* Alert cooldown to reduce repeated alerts

---

## Detection Rules

ADAPTIVE-IDS v1.0 currently includes four detection rules.

### 1. TCP SYN Port Scan

Detects multiple TCP SYN connection attempts from the same source targeting different destination ports within a short time window.

**Current threshold:**

* 10 unique destination ports
* Within 5 seconds

**Severity:** HIGH

---

### 2. UDP Scan

Detects UDP traffic from the same source targeting multiple destination ports within a short time window.

**Current threshold:**

* 10 unique destination ports
* Within 5 seconds

**Severity:** HIGH

---

### 3. ICMP Flood

Detects an unusually high number of ICMP packets from the same source within a short time window.

**Current threshold:**

* 20 ICMP packets
* Within 5 seconds

**Severity:** HIGH

---

### 4. TCP SYN Flood

Detects excessive TCP SYN connection attempts from the same source within a short time window.

**Current threshold:**

* 20 SYN packets
* Within 5 seconds

**Severity:** HIGH

---

> **Note:** These are heuristic, rule-based detections intended for learning and experimentation. A triggered rule indicates traffic matching the configured pattern; it does not by itself prove malicious intent.

---

## Dashboard

The project includes a Flask-based web dashboard for monitoring network activity in real time.

### Dashboard sections

* **Traffic Overview**

  * Total packets
  * TCP packets
  * UDP packets
  * ICMP packets
  * ARP packets
  * Other packets

* **Detection Rules**

  * Displays currently active detection mechanisms

* **Security Alerts**

  * Alert time
  * Severity
  * Detection type
  * Source IP
  * Description

* **Live Packet Log**

  * Timestamp
  * Protocol
  * Source
  * Destination
  * Packet information

The dashboard automatically refreshes to display current network activity and generated alerts.

---

## Architecture

The current architecture keeps packet processing and the web interface separate.

```text
                    Network Interface
                           │
                           ▼
                    Packet Capture
                           │
                           ▼
                    Packet Processing
                           │
             ┌─────────────┼─────────────┐
             │             │             │
             ▼             ▼             ▼
          Traffic       Detection     Packet
         Statistics       Rules        Log
                           │
                           ▼
                     Security Alert
                           │
                           ▼
                    Flask REST API
                           │
                           ▼
                    Web Dashboard
```

---

## Project Structure

```text
ADAPTIVE-IDS/
│
├── ids.py
├── app.py
├── README.md
│
└── ui/
    ├── templates/
    │   └── dashboard.html
    │
    └── static/
        └── css/
            └── dashboard.css
```

### File Overview

**`ids.py`**

Contains the core IDS functionality:

* Packet capture
* Traffic statistics
* Packet processing
* Detection rules
* Security alert generation

**`app.py`**

Runs the Flask application and exposes API endpoints used by the dashboard.

**`dashboard.html`**

Contains the dashboard interface and JavaScript used to retrieve live data.

**`dashboard.css`**

Contains the dashboard styling and responsive layout.

---

## Technologies Used

* **Python**
* **Scapy**
* **Flask**
* **HTML**
* **CSS**
* **JavaScript**
* **Linux / Kali Linux**
* **Git & GitHub**

---

## Requirements

* Python 3
* Scapy
* Flask
* Linux environment with access to a network interface
* Root/sudo privileges for packet capture

Install the required Python packages:

```bash
pip install scapy flask
```

On Kali Linux, you may use:

```bash
pip3 install scapy flask
```

---

## Running ADAPTIVE-IDS

Clone the repository:

```bash
git clone git@github.com:devcyan/ADAPTIVE-IDS.git
```

Enter the project directory:

```bash
cd ADAPTIVE-IDS
```

Install dependencies:

```bash
pip3 install scapy flask
```

Set the network interface in `ids.py`:

```python
INTERFACE = "eth1"
```

Then start the application:

```bash
sudo python3 app.py
```

Open the dashboard in a browser:

```text
http://127.0.0.1:5000
```

---

## Testing

The current detection rules were tested using controlled network traffic in a local lab environment.

### TCP SYN Port Scan

Tested using Nmap:

```bash
sudo nmap -Pn -sS -e eth1 -p 1-20 <target-ip>
```

### UDP Scan

```bash
sudo nmap -Pn -sU -e eth1 -p 1-20 <target-ip>
```

### ICMP Flood

```bash
sudo ping -f -c 50 <target-ip>
```

### TCP SYN Flood

Tested using controlled TCP SYN traffic:

```bash
sudo hping3 -S -p 80 --flood -c 50 <target-ip>
```

The generated traffic was observed by ADAPTIVE-IDS and corresponding alerts were displayed in the dashboard.

> Testing should only be performed on systems and networks that you own or have explicit permission to test.

---

## Design Approach

ADAPTIVE-IDS is intentionally being developed in stages.

Instead of starting with a large security-monitoring architecture, the project began with basic packet capture and is being expanded as new requirements appear.

### Development direction

```text
Basic Packet Capture
        │
        ▼
Traffic Statistics
        │
        ▼
Live Monitoring Dashboard
        │
        ▼
Rule-Based Detection
        │
        ▼
Security Alerts
        │
        ▼
Persistent Event & Alert Storage
        │
        ▼
Advanced Detection
        │
        ▼
Response / Prevention Capabilities
```

This incremental approach allows each stage to be implemented and tested before introducing additional complexity.

---

## Current Limitations

ADAPTIVE-IDS v1.0 is an early-stage project and has several limitations:

* Detection is currently rule-based.
* Thresholds are manually configured.
* Detection rules use heuristic patterns and may produce false positives.
* Alerts are currently maintained in memory.
* Recent packet and alert views are limited to the current application session.
* Raw packets are inspected but not permanently stored.
* There is currently no authentication system for the dashboard.
* The system is currently designed primarily for a controlled Linux-based lab environment.

These limitations are part of the project's current development stage.

---

## Future Development

Future versions may introduce capabilities such as:

* Persistent event and alert storage
* MySQL-based security event management
* Historical event search
* Advanced filtering and investigation
* Additional detection rules
* Statistical traffic analysis
* Anomaly detection
* Machine-learning-assisted detection
* Automated response capabilities
* IDS-to-IPS evolution
* Centralized security monitoring concepts

Future features will be introduced incrementally and tested as they are implemented.

---

## Project Goal

The long-term goal of ADAPTIVE-IDS is to evolve from a basic network IDS into a broader security monitoring and response system.

The project focuses on learning and demonstrating the practical development of cybersecurity tooling—from packet capture and network analysis to detection, alerting, investigation, and eventually automated response.

---

## Disclaimer

ADAPTIVE-IDS is an educational and experimental cybersecurity project.

Only use the packet capture, scanning, flooding, and detection-testing capabilities on networks and systems where you have authorization.

---

## Author

**Dev Zende**

Cybersecurity Student | Security & Network Monitoring Enthusiast

GitHub: **devcyan**
