# Incident Investigation & Case Report
**Case Reference:** CDL-INC-2026-08  
**Associated Hunt/Rule ID:** CDL-HUNT-2026-01 / CDL-SIG-101  
**Target Machine Name:** WORKSTATION-ENG04  
**Impact Level:** High  
**Status:** Closed (Case Resolution Complete)  

## 1. Executive Summary
Anomalous command execution and outbound network beacons were detected on machine `WORKSTATION-ENG04`. Investigation confirmed that an engineer executed a malicious payload delivered via an attachment, resulting in local credential harvesting attempts and outbound persistence loops to a known command-and-control node.

## 2. Technical Timeline of Attacker Actions
All timestamps are normalized and extracted directly from the raw Mordor and EVTX logs:

*   **2026-11-05T02:14:10Z** | `EVTX ID 4624 (Logon Type 2)` | Local user interaction initiated session for user `j.doe`.
*   **2026-11-05T02:18:22Z** | `Sysmon ID 1` | `outlook.exe` spawned an anomalous child process: `cmd.exe /c "powershell.exe -nop -w hidden -enc aXdl...[truncated]..."`.
*   **2026-11-05T02:18:45Z** | `Sysmon ID 11` | File creation event recorded: `C:\Windows\Temp\update_svc.exe` written to disk.
*   **2026-11-05T02:19:01Z** | `Sysmon ID 10` | Process access request directed at `C:\Windows\System32\lsass.exe` by source `update_svc.exe` with access mask `0x1010`. (Triggered detection rule `CDL-SIG-101`).
*   **2026-11-05T02:19:15Z** | `Zeek Conn` | Continuous asynchronous TCP handshake check-ins initiated to external target destination `185.220.101[.]5:443`.

## 3. Root Cause Analysis (RCA)
The root cause was identified as **User Execution of Malicious Content (T1204.002)** via a social engineering spear-phishing attachment. The endpoint validation layer failed to block execution because the payload executed via an encoded PowerShell script launched directly out of an authorized parent productivity application profile (`outlook.exe`).

## 4. Impact Assessment
*   **Confidentiality:** High Risk. Memory extraction flags indicate local user identity cache databases (`lsass.exe` state) were parsed. 
*   **Integrity:** Compromised. The adversary achieved remote control script execution privileges on the endpoint node.
*   **Availability:** Non-impacted. No destructive or encryption modules (ransomware logic) were detected within the execution streams.

## 5. Closure Classification & Justification
*   **Final Classification:** **True Positive (Malicious Activity)**.
*   **Justification:** Definitive telemetry artifacts confirm the execution loop: arbitrary process spawning via an email application, explicit credential memory access hooks, and persistent external communications matching automated network signatures. 
*   **Detection Gaps Identified:** Standard endpoint execution policies lacked strict parent-child process restrictions (e.g., blocking Office applications from spawning scripting shells). Recommended mitigation rule added to the engineering tuning project.
