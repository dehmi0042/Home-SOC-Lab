# Home-SOC-Lab
# 🛡️ Home SOC Lab – SIEM Threat Detection

---

## 🎯 Objective

The **Home SOC Lab** project was designed to build a simulated **Security Operations Center (SOC)** environment for detecting and analyzing cyber attacks using **Splunk SIEM**.  
The goal was to ingest, visualize, and correlate logs from multiple systems (Windows, Linux, and Active Directory) to identify malicious behavior patterns such as brute-force attacks and PowerShell abuse.  

This hands-on project strengthened understanding of **threat detection engineering**, **log analysis**, and **incident response workflows**.

---

## 🧠 Skills Learned

- Practical implementation of a **SIEM environment** (Splunk)  
- Analysis and correlation of logs from Windows, Linux, and Sysmon  
- Creation of **Splunk SPL detection rules** and dashboards  
- Understanding **MITRE ATT&CK** tactics for common adversarial behaviors  
- Configuring log forwarders (Winlogbeat, Syslog, and Splunk Universal Forwarder)  
- Network configuration and isolation using **VirtualBox NAT/Host-only** networks  
- Development of documentation and incident reports  

---

## 🧰 Tools Used

- **Splunk**  
- **Windows Server 2025 (Active Directory)** 
- **Windows 11 Client**  
- **Ubuntu Server**  
- **Sysmon & Winlogbeat**  
- **VirtualBox**
- **PowerShell & Hydra**  
---

## 🏗️ Steps:

### 🖥️ Step 1 – Lab Architecture

The following diagram provides an overview of the SOC lab environment.
It includes a Splunk Server, Active Directory Domain Controller, Windows 11 endpoint, Ubuntu Server, and Kali attacker machine, all connected on the same virtual network (192.168.10.0/24).
Each host contributes logs to Splunk through Sysmon and Splunk Universal Forwarder, while Atomic Red Team and Kali are used to generate realistic attack telemetry.

📸  
![Network Diagram](screenshots/setup.png)
*Network topology of the lab (Splunk, AD, Windows client, Ubuntu attacker).*

---

### ⚙️ Step 2 – Splunk Setup & Log Ingestion

**Ref 2: Splunk Configuration**

📸  
![Splunk](screenshots/splunk_dashbored.png)
*Splunk Enterprise web UI — main dashboard.*

Splunk Enterprise successfully installed and running on 192.168.10.10:8000, and collects logs from Sysmon, Winlogbeat, and the Universal Forwarder.


![Logs](screenshots/logs_source.png)
*Configured Splunk inputs to receive event logs*

Windows Sysmon, Winlogbeat, and Linux Syslog sources via Universal Forwarder on port 9997.
Validation of log ingestion from all endpoints. Splunk indexes confirm receipt of data from Windows 11, Ubuntu Server, and Active Directory hosts

---

### 💥 Step 4 – Simulating Attacks

An SSH/RDP brute-force and Atomic Red Team attack was launched against the Windows Server and Ubuntu Server to generate realistic log data.

**Ref 4.1: Brute Force RDP Simulation**

📸  
![attack_command](screenshots/brute_force_attack_rdp.png)
*Brute Force Attack aginst Windows11 (RDP) using Hydra*


![Failed Login Events](screenshots/brute_force_attack_rdp_log.png)
*The attack produced multiple failed authentication events (Event ID 4625).*


**Ref 4.2: Brute Force SSh Simulation**


📸  
![attack Command](screenshots/brute_force_attack_ssh.png)
*Brute Force Attack aginst Ubuntu server (SSh) using Hydra*


![Failed login](screenshots/brute_force_attack_ssh_log.png)
*The attack produced multiple failed password events.*


**Ref 4.2: Atomic Red Team — T1136.001 (Create Account)**

A short, controlled Atomic Red Team exercise (technique **T1136.001 — Create Account: Local Account**) was executed. The test used a PowerShell command to create a local account and exercise related activity; the resulting events were ingested into Splunk for verification and tuning.


![powershell command](screenshots/atomic_red_team.png)
*PowerShell command used to execute the Atomic Red Team test (T1136.001).*

**Detected Event Codes:**  
- **4720** — A user account was created  
- **4722** — A user account was enabled  
- **4724** — An attempt was made to reset an account password  
- **4726** — A user account was deleted

![eventlog](screenshots/atomic_red_team_4720_log.png)

![eventlog](screenshots/atomic_red_team_4722_log.png)

![eventlog](screenshots/atomic_red_team_4724_log.png)

![eventlog](screenshots/atomic_red_team_4726_log.png)
*Windows Security Event Logs generated during the simulation.*

The test confirmed that account creation and modification activities are properly logged and detectable within the Windows Event Log system and SIEM.

---

### 🚨 Step 5 – Incident Report

### 1. Brute-Force RDP Attack on Windows

**Date/Time:** 2025-10-18, 22:58  
**Source:** `192.168.10.20` (Kali)  
**Target:** `192.168.10.5` (Windows 11, User: `BSmth@myLab.local`)  
**MITRE ATT&CK Technique:** [T1110.001 – Brute Force: RDP](https://attack.mitre.org/techniques/T1110/001/)  

**Detection Evidence:**
- Multiple failed RDP logins detected by Splunk, EventCode `4625`.
- Alert triggered for excessive failed authentication attempts by account and source IP.

**Response Actions:**
- Review for successful unauthorized logins.
- Enforce account lockout policies and enhance password complexity.
- Investigate affected accounts for signs of compromise.

***

### 2. Brute-Force SSH Attack on Ubuntu

**Date/Time:** 2025-10-19, 20:04  
**Source:** `192.168.10.20` (Kali)  
**Target:** `192.168.10.7` (Ubuntu Server, User: `abdul`)  
**MITRE ATT&CK Technique:** [T1110 – Brute Force](https://attack.mitre.org/techniques/T1110/)  

**Detection Evidence:**
- Repeated failed SSH login attempts logged in `/var/log/auth.log`.
- Splunk dashboard flagged login pattern as brute-force; valid credential discovered.

**Response Actions:**
- Change credentials for affected account immediately.
- Switch SSH authentication to key-based or implement rate-limiting.
- Monitor for further attack patterns and block offending sources.

***

### 3. Atomic Red Team – Local Account Creation (Windows)

**Date/Time:** 2025-10-19, 19:35  
**Source:** Windows PowerShell (Atomic Red Team Test)  
**Target:** Windows Client (Active Directory environment)  
**MITRE ATT&CK Technique:** [T1136.001 – Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/)  

**Detection Evidence:**
- PowerShell test executed; triggered EventCodes:
    - `4720` – Account creation
    - `4722` – Account enabled
    - `4724` – Password reset
    - `4726` – Account deletion
- Events successfully ingested and visualized in Splunk.

**Response Actions:**
- Confirm monitoring of all account changes in SIEM.
- Review privilege escalation attempts tied to local accounts.
- Maintain audit logs and alert on administrative PowerShell use.

***

### Incident Summary Table

| Incident                  | MITRE Technique     | Evidence/EventCodes      | Source → Target         | Response Action           |
|---------------------------|--------------------|-------------------------|-------------------------|---------------------------|
| RDP Brute-Force (Win)     | T1110.001 (RDP)    | 4625                    | 10.20 → 10.5            | Lockout, analyze, review  |
| SSH Brute-Force (Ubuntu)  | T1110 (SSH)        | /var/log/auth.log       | 10.20 → 10.7            | Change pw, enforce keys   |
| Atomic Create Account     | T1136.001          | 4720,4722,4724,4726     | Win-Client (internal)   | Monitor, restrict abuse   |
