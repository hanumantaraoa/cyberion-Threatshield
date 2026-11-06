# Incident Response Playbook: Command & Control Beaconing
**Identifier:** CDL-IRP-003  
**Target Framework Mapping:** MITRE ATT&CK T1071 (Application Layer Protocol)  
**Classification:** Internal Use — SOC Operations  

## 1. Trigger Conditions
* Threat hunt output isolates a host with a high volume of persistent, low-variance asynchronous connections to an external IP.
* Firewalls or proxies flag traffic matching known threat intelligence Command and Control (C2) domains.
* Execution of a binary spawning suspicious, persistent socket requests over HTTP/S or DNS protocols.

## 2. Phase 1: Identification & Verification
1. **Statistical Verification:** Run jitter and delta-time variance scripts to verify that connection intervals point to an automated script heartbeat rather than standard web browsing.
2. **Header Audit:** Inspect proxy telemetry to extract anomalous User-Agent values, unusual HTTP request methods, or non-standard SSL certificate parameters.
3. **Threat Intel Lookup:** Query reputable threat intelligence platforms to establish known malicious associations for the destination IP or domain indicators.

## 3. Phase 2: Containment
1. **Layer-7 Edge Blocking:** Configure corporate proxy and perimeter firewall rule objects to immediately drop traffic targeting the malicious external IPs and domains.
2. **Endpoint Quarantine:** Isolate the calling endpoint machine from both the internal environment and general Internet access paths.
3. **DNS Sinkholing:** Redirect requests for the malicious domain string to a localized loopback address within internal DNS server spaces.

## 4. Phase 3: Eradication & Recovery
1. **Payload Extraction:** Locate and terminate the persistence wrapper process (e.g., task scheduler triggers, registry run key paths) initiating the network calls.
2. **Device Cleanse:** Cleanse volatile host memory workspaces, delete malicious binaries, or perform a clean golden-image endpoint deployment sequence if deep tampering is suspected.
3. **Egress Review:** Audit firewalls to verify that no other environment nodes are attempting traffic trajectories toward the blocked external endpoints.

## 5. Phase 4: Follow-up & Stakeholder Communications
1. **Internal Escalation:** Escalate metrics immediately to the Director of Security Operations and the Threat Intelligence Advisory office.
2. **Post-Incident Action:** Incorporate the discovered Indicators of Compromise (IPs, hashes, domain targets) into localized threat watchlists to automate future detection phases.
