# Incident Response Playbook: Credential Compromise & Dumping
**Identifier:** CDL-IRP-001  
**Target Framework Mapping:** MITRE ATT&CK T1003 (OS Credential Dumping)  
**Classification:** Internal Use — SOC Operations  

## 1. Trigger Conditions
* Alert fires for Sigma Rule `cdl-sig-101` (LSASS Process Access).
* Alert fires for Sigma Rule `cdl-sig-102` (Registry Hive Export via CLI).
* Endpoint Detection (EDR) flags suspicious memory reads of `lsass.exe` or creation of `.dmp` files in public directories.

## 2. Phase 1: Identification & Verification
1. **Process Analysis:** Open your Jupyter parsing engine or SIEM workspace. Verify the `SourceImage` and `CommandLine` that targeted `lsass.exe`.
2. **Access Mask Audit:** Confirm if the `GrantedAccess` field matches high-risk masks (`0x1010` or `0x1F1FFF`).
3. **Corroborate Telemetry:** Cross-reference Windows Security logs for unexpected use of administrative tools (`mimikatz.exe`, `procdump.exe`, `comsvcs.dll` via `rundll32`).

## 3. Phase 2: Containment
1. **Network Isolation:** Immediately isolate the impacted host (`WORKSTATION-XXXX`) from the local network segment using endpoint network quarantine controls.
2. **Credential Invalidation:** Revoke all active Kerberos Ticket Granting Tokens (TGT) and interactive sessions for any user logged into that host within the last 24 hours.
3. **Account Status:** Force an immediate password reset for impacted domain and local administrator accounts.

## 4. Phase 3: Eradication & Recovery
1. **Process Termination:** Kill the parent and child processes identified as the ingestion source of the dumping activity.
2. **Artifact Deletion:** Delete any generated memory dumps (e.g., `*.dmp`, `sam`, `security`, `system` hive files) from the file system.
3. **System Scan:** Run a full anti-malware and configuration integrity scan on the host workspace to confirm no persistent backdoors remain.

## 5. Phase 4: Follow-up & Stakeholder Communications
1. **Internal Escalation:** Notify the Identity & Access Management (IAM) engineering lead and the CIRT director within **2 hours** of confirmation.
2. **Post-Incident Action:** Document the timeline and missing application controls in the incident repository to feed back into detection tuning passes.
