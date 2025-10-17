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

## 🏗️ Steps & Setup Overview

> Each step includes related screenshots and explanations.  
> *(Upload your screenshots in the `screenshots/` folder or to Imgur and link using `![Description](URL)`.)*

---

### 🖥️ Step 1 – Lab Architecture

**Ref 1: Network Diagram**

The following diagram shows the SOC lab network topology, consisting of Splunk, Windows Server, Client, and Ubuntu machines.  
Each machine was connected using a NAT + Host-only network for isolation and communication.

📸  
![Network Diagram](diagrams/network_topology.png)

---

### ⚙️ Step 2 – Splunk Setup & Log Ingestion

**Ref 2: Splunk Configuration**

Splunk Enterprise (Free Edition) was installed on the main analysis VM.  
Logs from Sysmon, Winlogbeat, and Syslog were ingested into Splunk using configured inputs.

📸  
![Splunk Inputs Configuration](screenshots/splunk_inputs.png)

---

### 🧩 Step 3 – Sysmon & Winlogbeat Configuration

**Ref 3: Windows Logging Setup**

Sysmon was deployed with a custom configuration to capture detailed process, network, and registry events.  
Winlogbeat forwarded these logs to Splunk via port `9997`.

📸  
![Sysmon Logs in Splunk](screenshots/sysmon_event_log.png)

---

### 💥 Step 4 – Simulating Attacks

**Ref 4: Brute Force Simulation**

An SSH brute-force attack was launched from the Ubuntu attacker machine against the Windows Server to generate realistic log data.  
The attack produced multiple failed authentication events (Event ID 4625).

📸  
![Failed Login Events](screenshots/failed_logins.png)

---

### 🚨 Step 5 – Detection Rules & Alerts

**Ref 5: SPL Detection Query**

A Splunk SPL rule was created to detect multiple failed login attempts within a short timeframe, triggering a brute-force alert.

```spl
index=security sourcetype=WinEventLog:Security EventCode=4625
| stats count by Account_Name, IpAddress
| where count > 5
