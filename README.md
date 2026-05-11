# Solenya Integrity Engine

The Solenya Integrity Engine is a zero-dependency, event-driven File Integrity Monitor (FIM) and persistence detection framework for Windows environments. 

**Project Status: Ongoing Development**
This tool is designed specifically for security research, testing, and academic exploration. **It is not designed to replace sophisticated commercial Endpoint Detection and Response (EDR) platforms**, nor is it intended to act as a primary, enterprise-wide persistence analytics tool. 

Instead, Solenya is engineered to be a *supplementary* analytics engine. It is an academic framework intended to demonstrate advanced cybersecurity concepts—enabling practitioners, students, and researchers to study, test, and understand persistence mechanisms without needing a corporate budget, university courses, or nation-state adversaries.

## Ethical Use & Liability Disclaimer
This framework is provided "as is" strictly for defensive engineering, security research, and authorized systems administration. It is not intended to be utilized as malicious command-and-control (C2) infrastructure, nor should it be used to deploy monitoring payloads to unauthorized endpoints. 

As the end-user, it is your absolute and sole responsibility to ensure that your usage of this tool-like the deployment of endpoint agents and the localized collection of system telemetry-is strictly ethical, legally compliant, and explicitly authorized by the owners of the target infrastructure. You must ensure your deployment complies with your organizational and regional data privacy policies. The authors and contributors assume no liability and are not responsible for any misuse, damage, privacy violations, or legal consequences resulting from the deployment or modification of this software.

## Architecture
The framework operates on a lightweight, decoupled client-server architecture:

1. **The Endpoint Agent (`Agent.ps1`):** A strictly native PowerShell script that executes via a hidden Scheduled Task triggered exclusively by Windows Event ID 4657 (Registry Modification). It utilizes DPAPI to maintain an encrypted local state cache, calculates cryptographic hashes, monitors execution arguments, and transmits telemetry to the central server.
2. **The Central Server (`Listener.ps1`):** A standalone, asynchronous HTTPS server that ingests telemetry into a high-speed, in-memory `.NET` DataTable. It features Bulk Ingest Protection to handle massive baseline drops without threading bottlenecks. It dynamically queries external Threat Intelligence APIs using keys decrypted directly into volatile RAM, ensuring zero hardcoded secrets.
3. **The Management Dashboard (`index.html`):** A zero-dependency, static HTML/JS single-page application served directly from the Server's memory. It provides contextual triage, dynamic endpoint filtering, localized timezone shifting, and multi-format data extraction.

## Core Capabilities
* **Zero-Trust File Integrity:** Mathematically binds file SHA-256 hashes to their execution arguments. If a binary is altered, or if a baseline binary's arguments are hijacked, the engine flags the state change.
* **Persistence Interrogation:** Natively monitors Services (T1543.003), Run Keys (T1547.001), WMI Event Subscriptions (T1546.003), and COM Hijacking (T1546.015).
* **Automated Triage:** Built-in heuristics scan for Living-off-the-Land (LOLbin) abuse, suspicious byte-sequences, and fileless execution patterns (Base64/Hidden windows).
* **Threat Intelligence Routing:** Natively integrates with VirusTotal, AlienVault OTX, MISP, or custom proprietary APIs for automated hash validation.

---

## Deployment Guide

### Step 1: Central Server Configuration (`Setup.ps1`)
**Where to execute:** Run this only on your designated Central Server (the machine that will host the Listener and Dashboard).

This utility interactively configures your architecture. It permanently modifies the code inside `Agent.ps1` and `Listener.ps1` to match your environment's specific routing and security requirements.

* **Option 1 - Endpoint Routing:** You will be prompted to enter the IP address or FQDN of your Central Server. `Setup.ps1` injects this IP into `Agent.ps1` so the endpoints know exactly where to send their telemetry.
* **Option 2 - SSL/TLS Architecture:**
    * *Auto-Generate (Default):* Instructs the Server to create a temporary, self-signed certificate for encrypted HTTPS traffic.
    * *Enterprise Certificate:* Allows you to input a specific SHA-1 thumbprint. The Server will bind strictly to that validated PKI infrastructure.
* **Option 3 - Threat Intelligence Integration (Zero-Trust Storage):**
    * *[1] VirusTotal (Free Tier):* Enables VT integration but strictly enforces a 15-second cooldown in the dashboard UI to protect your IP from being rate-limited.
    * *[2] VirusTotal (Paid Tier):* Unlocks the UI for rapid, nominal 2-second scanning.
    * *[3] AlienVault OTX:* Integrates community-driven pulse detection. Operates on the rapid 2-second UI refresh timer.
    * *[4/5] MISP / Custom API:* Allows you to input a custom bearer token and URL construct to route telemetry to your own proprietary intel engines.
    * *[6] DISABLED:* The engine will rely entirely on local, zero-trust heuristics.
    * *(Note: Your API key is cryptographically sealed to the server using DPAPI. It is never stored in plaintext.)*

### Step 2: Initialize the Central Server (`Listener.ps1`)
**Where to execute:** On your Central Server.

Start the telemetry aggregator as an Administrator. This will bind to `0.0.0.0:443`, establish the in-memory database, and begin listening for endpoint check-ins.
*(Warning: Do not expose this port directly to the public internet without proper reverse-proxy and firewall configurations.)*

### Step 3: Arm the Endpoints (`Deploy.ps1`)
**Where to execute:** On the target Windows workstations or servers you wish to monitor.

Copy the configured repository to the endpoint and run `Deploy.ps1` as Administrator. 
This script performs the following critical actions:
1. Establishes a secure `C:\ProgramData\SolenyaEngine` directory with `SYSTEM`-only ACLs.
2. Enables global Registry Auditing (AuditPol) and applies specific System Access Control Lists (SACLs) to persistence hives (Services, Run Keys).
3. Registers the Event-Driven Scheduled Task to execute `Agent.ps1` invisibly whenever Event ID 4657 is triggered.
The agent will immediately execute once to establish the endpoint's cryptographic baseline.

### Step 4: Access the Dashboard
From any browser able to route to your Central Server, navigate to `https://<Your-Server-IP>/dashboard` to view the localized UI, configure contextual whitelist rules, and export telemetry in CSV, JSON, or TXT formats.

---

## Validation & Emulation
To safely validate the engine's detection capabilities and study persistence mechanics without introducing real malware, this repository includes two benign emulation scripts. These scripts safely replicate advanced adversarial techniques to trigger the engine's heuristic analysis.

**1. Standard Emulation (`Tester.ps1`)**
This script establishes anomalous persistence by registering a native, benign Windows binary (`calc.exe`) as a background service. It safely demonstrates how the engine detects **Living-off-the-Land (LOLbin)** abuse (MITRE T1543.003) and contextualizes it as a CRITICAL risk.

**2. Advanced Emulation (`Advanced_Tester.ps1`)**
This script simulates a fileless execution sequence. It creates a service that executes a Base64-encoded PowerShell payload (which simply prints a benign test message). It safely demonstrates the engine's **Behavioral Heuristics** and its ability to detect anomalous execution arguments and command-line obfuscation.

*Note: After running these emulations and observing the telemetry in the dashboard, you can use `Scrubber.ps1` to cleanly remove the test services from your operating system.*

---

## Removal
To completely remove the architecture from an endpoint, run `.\Scrubber.ps1` as Administrator on the target machine. This unregisters the background task, purges the DPAPI state memory, violently kills any remaining test services via WMI, and removes the registry SACLs, returning the endpoint to its original state.

## Contributions & Future Development: Democratizing Cybersecurity
The field of cybersecurity is often locked behind expensive enterprise tooling and proprietary data silos. The Solenya Integrity Engine was built to help democratize access to high-fidelity telemetry and systems engineering concepts. 

This project is in active, ongoing development, and we welcome contributions from the open-source community. Whether you are a seasoned malware reverse-engineer or a student writing your first PowerShell script, your pull requests are encouraged. 

**Future Roadmap & Areas for Contribution:**
* **Execution Chaining:** Integrating Sysmon (Event ID 1) logic to map persistence alerts back to their parent process trees.
* **Alerting Pipelines:** Developing native webhooks to route critical telemetry to Slack, Discord, or Microsoft Teams.
* **Cross-Platform:** Designing a Linux equivalent utilizing `systemd` and `auditd`.
* **Heuristic Expansion:** Enhancing the native byte-sequence scanning to detect newer evasion vectors.

## Development Transparency
This project was developed through a collaborative effort between a human Security Architect and a Large Language Model (Google Gemini). 

* **Human Contribution:** The human architect defined the strategic requirements, designed the event-driven (Event ID 4657) architecture, identified logical flaws (such as transient amnesia and argument-hijacking evasion vectors), and directed the integration of contextual triage workflows (AlienVault OTX, MITRE ATT&CK mapping).
* **AI Contribution:** The AI generated the underlying PowerShell and JavaScript code, implemented the asynchronous `.NET` threading models, structured the in-memory database logic, engineered the DPAPI credential wrapping, and developed the responsive front-end dashboard including dynamic filtering and multi-format data extraction.

## License
**MIT License**
Copyright (c) 2026

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
