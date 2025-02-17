<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
## 📂 [Scenario Creation](https://github.com/rasheedjimoh/threat-hunting-scenario-tor/blob/main/event-creation.md)

---

## ⚙️ Platforms and Languages Leveraged
- **Operating System:** Windows 10 Virtual Machines (Microsoft Azure)  
- **EDR Platform:** Microsoft Defender for Endpoint  
- **Query Language:** Kusto Query Language (KQL)  
- **Browser Investigated:** Tor Browser  

---

## 📝 Scenario Overview
Management suspects unauthorized usage of the TOR browser to bypass network security controls. The suspicion stems from:  
- Recent network logs showing unusual encrypted traffic patterns.  
- Connections to known TOR entry nodes.  
- Anonymous reports from employees suggesting access to restricted sites during work hours.  

**Objective:** Detect any TOR usage, investigate associated security incidents, and promptly notify management if usage is confirmed.

---

## 🛡️ High-Level IoC (Indicators of Compromise) Discovery Plan
To identify TOR-related activity, the following checks were performed:

1. **DeviceFileEvents** – Detect `tor(.exe)` or `firefox(.exe)` file activities.  
2. **DeviceProcessEvents** – Identify installation and execution of the TOR browser.  
3. **DeviceNetworkEvents** – Find outgoing connections to known TOR ports and nodes.  

---

## 🚀 Investigation Steps and Results

### 🟡 Step 1: File Activity Analysis – `DeviceFileEvents`
- **Objective:** Identify any TOR-related files downloaded or created.  
- **Result:** Found that the user *employee* downloaded the TOR installer and created a `tor-shopping-list.txt` file on the desktop.  

**Query:**
```kql
DeviceFileEvents  
| where DeviceName == "threat-hunt-lab"  
| where InitiatingProcessAccountName == "employee"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2024-11-08T22:14:48.6065231Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

**Evidence:**  
- 📁 **Downloaded File:** `tor-browser-windows-x86_64-portable-14.0.1.exe`  
- 📝 **File Created:** `tor-shopping-list.txt` on desktop  
- 🕒 **Time:** `2024-11-08T22:14:48.6065231Z` to `2024-11-08T22:27:19.7259964Z`  

---

### 🟠 Step 2: Process Analysis – TOR Browser Installation (`DeviceProcessEvents`)
- **Objective:** Detect if the TOR browser was installed and how.  
- **Result:** Found that *employee* ran the installer in *silent mode*, indicating intentional and concealed installation.  

**Query:**
```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.1.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```

**Evidence:**  
- 🖥️ **Device:** `threat-hunt-lab`  
- 👤 **User:** `employee`  
- 🛠️ **Installer:** `tor-browser-windows-x86_64-portable-14.0.1.exe`  
- 💻 **Command:** Silent install (`/S` flag)  
- 🕒 **Time:** `2024-11-08T22:16:47.4484567Z`  

---

### 🟢 Step 3: TOR Browser Execution Analysis – `DeviceProcessEvents`
- **Objective:** Confirm that the TOR browser was opened and used.  
- **Result:** Detected multiple `tor.exe` and `firefox.exe` processes, confirming the user launched the browser.  

**Query:**
```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```

**Evidence:**  
- 🖥️ **Device:** `threat-hunt-lab`  
- 👤 **User:** `employee`  
- 🚀 **Processes:** `tor.exe`, `firefox.exe` (TOR Browser)  
- 🕒 **First Launch Time:** `2024-11-08T22:17:21.6357935Z`  

---

### 🔴 Step 4: Network Activity Analysis – `DeviceNetworkEvents`
- **Objective:** Find network connections to known TOR nodes or ports.  
- **Result:** Discovered multiple TOR-related connections, including a connection to a known entry node (`176.198.159.33`) on port `9001`.  

**Query:**
```kql
DeviceNetworkEvents  
| where DeviceName == "threat-hunt-lab"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```

**Evidence:**  
- 🌐 **Outbound Connection:** Remote IP `176.198.159.33` on Port `9001`  
- 📍 **Local Proxy:** `127.0.0.1:9150`  
- 🖥️ **Process:** `tor.exe`  
- 🕒 **First Connection:** `2024-11-08T22:18:01.1246358Z`  

---

## 🧩 Chronological Event Timeline

| Timestamp (UTC)                | Event Description                                       |
|-------------------------------|-------------------------------------------------------|
| 2024-11-08T22:14:48.6065231Z | 📂 TOR installer downloaded (`tor-browser-windows-x86_64-portable-14.0.1.exe`). |
| 2024-11-08T22:16:47.4484567Z | ⚙️ Silent installation of the TOR browser executed. |
| 2024-11-08T22:17:21.6357935Z | 🚀 TOR browser (`tor.exe`, `firefox.exe`) launched. |
| 2024-11-08T22:18:01.1246358Z | 🌐 Network connection to known TOR node on port 9001. |
| 2024-11-08T22:18:16Z        | 🔁 Local proxy established at `127.0.0.1:9150`. |
| 2024-11-08T22:27:19.7259964Z | 📝 `tor-shopping-list.txt` created on the desktop. |

---

## 🛑 Summary of Findings
- The user **intentionally installed and launched the TOR browser** in a concealed (silent) manner.  
- Network activity confirmed **connections to known TOR nodes and ports**, indicating usage for anonymized browsing.  
- The creation of `tor-shopping-list.txt` suggests possible research or documentation of intended anonymous activities.  

---

## 🚨 Actions Taken
- **Device Isolation:** The device `threat-hunt-lab` was immediately isolated from the network.  
- **Management Notification:** The user’s direct manager was informed with supporting evidence.  
- **Security Report Submission:** This report is submitted to the incident response team for documentation and further analysis.  

---

## 📂 Additional Resources
- [🔗 Threat Hunting Scenario Creation](https://github.com/rasheedjimoh/threat-hunting-scenario-tor/blob/main/event-creation.md)  
- 📂 **Repository:** `github.com/rasheedjimoh/threat-hunting-scenario-tor`

---

**📌 Author:** Rasheed Jimoh  
**📅 Date:** February 17, 2025  
**🔐 Focus Area:** Threat Hunting and Incident Response  

---

*© Rasheed Jimoh. All rights reserved.* 🚀🔐
---
