# Incident Response Playbook: Lateral Movement via Remote Services
**Identifier:** CDL-IRP-002  
**Target Framework Mapping:** MITRE ATT&CK T1021 (Remote Services)  
**Classification:** Internal Use — SOC Operations  

## 1. Trigger Conditions
* Anomalous administrative network connections observed traversing internal network zone boundaries.
* Security Log `EventID 4624` (Logon Type 3 - Network) occurs rapidly across multiple workstations from a single source host.
* Execution alerts matching anomalous `PsExec.exe`, `wmic.exe`, or WinRM scripts traversing local subnets.

## 2. Phase 1: Identification & Verification
1. **Source Tracking:** Identify the initiating host IP address and the associated user account using your network connection log dataframes.
2. **Authentication Audit:** Verify if the authentication utilizes anomalous local admin accounts or compromised domain credentials.
3. **Share Monitoring:** Review Windows Security Event logs for connections targeting hidden administrative network shares (`Admin$`, `C$`).

## 3. Phase 2: Containment
1. **Microsegmentation:** Apply host-based or network firewall rule blocks to drop traffic on ports `135`, `445`, and `5985/5986` relative to the offending source device.
2. **Session Termination:** Log out all active remote network sessions stemming from the compromised pivot machine.
3. **Privileged Account Freeze:** Temporarily disable the specific Active Directory or local account being utilized to move horizontally across the segment.

## 4. Phase 3: Eradication & Recovery
1. **Service Cleanup:** Identify and delete any rogue Windows Services deployed by administrative execution vectors (e.g., PsExec services).
2. **Kill Pivot Tasks:** Terminate unauthorized persistent shells or script handlers running in the background of target machines.
3. **GPO Baseline Enforcement:** Force a Group Policy update to ensure local administrator restrictions are refreshed across all segment workstations.

## 5. Phase 4: Follow-up & Stakeholder Communications
1. **Internal Escalation:** Alert the Infrastructure Engineering group and Network Operations (NetOps) team leads immediately.
2. **Post-Incident Action:** Update the MITRE coverage matrix to account for any internal network visibility gaps exposed during the lateral loop.
