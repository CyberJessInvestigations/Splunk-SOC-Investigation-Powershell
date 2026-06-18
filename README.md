# Splunk SOC Investigation Portfolio

Splunk SOC investigation portfolio project using Splunk to investigate suspicious login activity, encoded PowerShell execution, outbound network connections, IOC extraction, MITRE ATT&CK mapping, dashboard creation, and severity classification.

# Splunk SOC Investigation: Suspicious Login and PowerShell Activity

## Project Overview

This project simulates a Tier 1 SOC investigation using Splunk. The investigation focuses on a high-severity alert involving suspicious login activity, obfuscated PowerShell execution, and outbound network connections from a Windows workstation.

The scenario centers on a workstation named `CORP-WS-042` and a user account named `jsmith`. The investigation uses Windows Security logs, PowerShell logs, and network connection logs to determine whether the activity represents suspicious or potentially malicious behavior.

## Objective

The goal of this project was to investigate a suspicious SIEM alert in Splunk, identify evidence of possible unauthorized access, analyze PowerShell activity, review outbound network connections, extract indicators of compromise, map findings to MITRE ATT&CK, and document the results in a professional SOC investigation report.

## Tools Used

* Splunk Enterprise
* SPL
* Windows Security Logs
* PowerShell Logs
* Network Connection Logs
* MITRE ATT&CK
* CyberChef
* GitHub

## Scenario

A SIEM alert was triggered for suspicious PowerShell execution on a Windows workstation used by a finance employee.

* Case ID: `SOC-2024-0315-001`
* Alert Name: Suspicious Login and PowerShell Activity
* Alert Time: `2024-03-15 14:32:17 UTC`
* Affected Host: `CORP-WS-042`
* Affected User: `jsmith`
* Internal Source IP: `10.10.5.42`
* External Destination IP: `185.220.101.47`
* Severity: High
* Status: Open — Under Investigation

## Data Sources

Three log sources were uploaded into Splunk under the index `soc_lab`:

| Source File                 | Description                                                          |
| --------------------------- | -------------------------------------------------------------------- |
| `windows_security_logs.csv` | Windows login activity, including failed and successful login events |
| `powershell_logs.csv`       | PowerShell execution and script block logging events                 |
| `network_connections.csv`   | Outbound network connection activity                                 |

The log ingestion was verified using the following SPL search:

```spl
index=soc_lab
| stats count by source
```

## Investigation Workflow

The investigation followed a structured SOC triage workflow:

1. Created a dedicated Splunk index named `soc_lab`
2. Uploaded Windows Security, PowerShell, and network connection logs
3. Verified log ingestion by counting events by source
4. Investigated failed and successful login activity
5. Reviewed suspicious PowerShell execution
6. Analyzed outbound network connections
7. Reconstructed the incident timeline
8. Built a four-panel SOC dashboard
9. Extracted indicators of compromise
10. Mapped the activity to MITRE ATT&CK
11. Classified the incident severity
12. Created a final SOC investigation report

## Key Findings

The investigation identified a suspicious sequence of activity involving the user `jsmith` and host `CORP-WS-042`.

Key findings included:

* Multiple failed login attempts for `jsmith`
* A successful login shortly after the failed attempts
* PowerShell execution using suspicious flags: `-nop`, `-w hidden`, and `-enc`
* Encoded PowerShell activity consistent with obfuscation
* A decoded command attempting to download a remote script
* Outbound connections from `powershell.exe` to `185.220.101.47`
* Network activity over ports `443` and `80`

This sequence suggests possible unauthorized access followed by suspicious PowerShell execution and external communication.

## Login Activity Analysis

Windows Security logs showed multiple failed login attempts followed by a successful login.

Important Windows Event IDs:

| Event ID | Meaning          |
| -------- | ---------------- |
| `4625`   | Failed login     |
| `4624`   | Successful login |

Several `4625` events were observed before a `4624` event. This pattern may indicate brute force or password guessing activity that eventually succeeded.

Example SPL used to label login events:

```spl
index=soc_lab source="windows_security_logs.csv" (event_id=4624 OR event_id=4625)
| eval login_result=case(event_id==4624, "Successful Login", event_id==4625, "Failed Login")
| table _time user event_id login_result
| sort _time
```

## PowerShell Analysis

PowerShell logs showed suspicious command-line activity involving the process `powershell.exe`.

Suspicious flags identified:

| Flag        | Meaning                                          |
| ----------- | ------------------------------------------------ |
| `-nop`      | Runs PowerShell without loading the user profile |
| `-w hidden` | Hides the PowerShell window                      |
| `-enc`      | Runs an encoded command                          |

These flags are commonly associated with malicious PowerShell activity because they can hide execution and make the command harder to read.

The decoded PowerShell command attempted to retrieve a remote script:

```text
http://185.220.101.47/payload.ps1
```

This behavior is suspicious because PowerShell was being used to reach out to an external IP address and download a script.

## Network Connection Analysis

Network connection logs showed outbound activity from `CORP-WS-042` to the external IP address `185.220.101.47`.

Observed connections:

| Source Host   | Destination IP   | Destination Port | Process          |
| ------------- | ---------------- | ---------------- | ---------------- |
| `CORP-WS-042` | `185.220.101.47` | `443`            | `powershell.exe` |
| `CORP-WS-042` | `185.220.101.47` | `80`             | `powershell.exe` |

This matters because `powershell.exe` connected to an external IP address. PowerShell does not normally make direct outbound web connections during regular user activity, so this activity is suspicious.

## Incident Timeline

| Time UTC            | Event                                       |
| ------------------- | ------------------------------------------- |
| `14:21:05–14:21:22` | Multiple failed login attempts for `jsmith` |
| `14:22:01`          | Successful login for `jsmith`               |
| `14:32:17`          | Suspicious PowerShell command executed      |
| `14:32:19`          | Outbound connection to `185.220.101.47:443` |
| `14:32:21`          | Outbound connection to `185.220.101.47:80`  |

The timeline shows a clear sequence: failed logins, successful login, encoded PowerShell execution, and outbound network communication. This supports the conclusion that the activity should be treated as suspicious and escalated.

## SOC Dashboard

A four-panel Splunk dashboard was created to organize the investigation evidence in one place.

| Panel                        | Purpose                                                 |
| ---------------------------- | ------------------------------------------------------- |
| Login Events Timeline        | Shows failed and successful login activity over time    |
| PowerShell Execution Events  | Displays PowerShell command-line activity               |
| Outbound Network Connections | Shows destination IPs, destination ports, and processes |
| Event Summary by Source      | Confirms event counts from each uploaded log source     |

Panels 2 and 3 were kept as tables because the raw command-line and connection details were more useful than charts for this part of the investigation.

## Indicators of Compromise

| Indicator Type          | Value                               | Confidence |
| ----------------------- | ----------------------------------- | ---------- |
| Host                    | `CORP-WS-042`                       | Confirmed  |
| User Account            | `jsmith`                            | Confirmed  |
| Internal Source IP      | `10.10.5.42`                        | Confirmed  |
| External Destination IP | `185.220.101.47`                    | High       |
| URL                     | `http://185.220.101.47/payload.ps1` | High       |
| File / Script Name      | `payload.ps1`                       | Medium     |
| Process                 | `powershell.exe`                    | High       |
| Command Flags           | `-nop`, `-w hidden`, `-enc`         | High       |

## MITRE ATT&CK Mapping

| Tactic              | Technique ID | Technique Name                  | Evidence                                                      |
| ------------------- | ------------ | ------------------------------- | ------------------------------------------------------------- |
| Initial Access      | `T1110`      | Brute Force                     | Multiple failed login attempts followed by a successful login |
| Execution           | `T1059.001`  | PowerShell                      | Suspicious PowerShell execution using `powershell.exe`        |
| Defense Evasion     | `T1027`      | Obfuscated Files or Information | Encoded command using `-enc`                                  |
| Defense Evasion     | `T1564.003`  | Hidden Window                   | PowerShell executed with `-w hidden`                          |
| Command and Control | `T1071.001`  | Web Protocols                   | Outbound connection to external IP over ports `443` and `80`  |
| Command and Control | `T1105`      | Ingress Tool Transfer           | Attempted download of `payload.ps1`                           |

User Execution was considered as a possible technique, but it was not included as a confirmed finding because the available Splunk evidence did not prove that the user manually opened or executed a malicious file.

## Severity Classification

**Severity: High**

This incident was classified as High because the activity happened in a suspicious sequence: failed login attempts, a successful login, encoded PowerShell execution, and outbound connections to an external IP address.

The incident was not classified as Critical because there was no confirmed evidence of ransomware, data exfiltration, privilege escalation, business disruption, or compromise across multiple systems.

## Recommended Response Actions

Recommended next steps include:

* Isolate `CORP-WS-042` from the network
* Disable or reset credentials for `jsmith`
* Block `185.220.101.47` at the firewall or proxy
* Search for the same indicators across other hosts
* Review PowerShell activity across the environment
* Preserve logs and artifacts for further investigation
* Continue monitoring for additional suspicious activity

## Report

The full SOC investigation report is included in this repository:

`SOC_Investigation_Report.pdf`

## Screenshots

Screenshots are included to document the investigation process, including:

* Splunk log ingestion verification
* Suspicious login activity
* PowerShell execution search
* Network connection search
* Incident timeline reconstruction
* SOC dashboard
* IOC and MITRE ATT&CK mapping
* Severity classification
* Final analyst report

## Repository Structure

```text
Splunk_SOC_Investigation_Portfolio/
│
├── README.md
├── report/
│   └── SOC_Investigation_Report.pdf
│
├── screenshots/
│   ├── 02_log_ingestion.png
│   ├── 03_login_search.png
│   ├── 04_powershell_search.png
│   ├── 05_network_search.png
│   ├── 06_timeline.png
│   ├── 07_dashboard.png
│   ├── 08_ioc_mitre_mapping.png
│   ├── 09_severity_decision.png
│   └── 10_report.png
│
├── spl_queries/
│   └── investigation_searches.spl
│
├── notes/
│   └── investigation_notes.md
│
├── iocs/
│   └── indicators_of_compromise.md
│
├── mitre/
│   └── mitre_mapping.md
│
└── dashboard/
    └── dashboard_summary.md
```

## Lessons Learned

This project strengthened my understanding of Splunk-based SOC investigations, Windows Event ID analysis, PowerShell detection, network connection review, IOC extraction, MITRE ATT&CK mapping, and incident severity classification.

The project also showed the importance of correlating multiple data sources. A single event may look suspicious, but the full timeline provides stronger evidence by connecting login activity, command execution, and outbound network communication.

## Disclaimer

This project was completed in a controlled lab environment using sample log data. No real systems were attacked, and no live malicious activity was performed. The purpose of this project is to demonstrate SOC investigation, Splunk search, IOC extraction, MITRE ATT&CK mapping, dashboard creation, and incident reporting skills.

## AI Use Disclosure

AI tools were used as a learning and documentation support resource for project planning, explanation, and writing refinement. All Splunk searches, screenshots, analysis decisions, and final conclusions were reviewed and completed by me.

## Contact

GitHub: CyberJessInvestigations
LinkedIn: [www.linkedin.com/in/jessicasansaricq](http://www.linkedin.com/in/jessicasansaricq)
Portfolio/YouTube: https://www.youtube.com/@CyberJessInvestigations
