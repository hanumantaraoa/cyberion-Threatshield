# Cyberion Threat Hunting Engagement Report
**Hunt Identifier:** CDL-HUNT-2026-01  
**Target Technique:** T1071.001 - Application Layer Protocol: Web Protocols (C2 Beaconing)  
**Assigned Hunter:** Individual Contributor Track Analyst  
**Dataset Under Analysis:** Splunk BOTS v3 & Zeek Network Logs  

## 1. Hypothesis Formulation
An internal endpoint has been compromised via an initial access vector and is actively beaconing to an attacker-controlled external Command and Control (C2) server. This beaconing manifest as automated, periodic network connections occurring at highly consistent time intervals (low jitter variance) to an unclassified external IP address.

## 2. Analytical & Query Methodology
To isolate the heartbeat check-ins from standard human web-browsing traffic (which exhibits high variance and random sleep intervals), the following processing pipeline is applied to the network telemetry dataset:
1. Filter network connection logs (`zeek_conn` or Splunk Common Information Model network traffic events) for outbound connections originating from internal subnets (`10.0.0.0/8`, `192.168.0.0/16`) to external destinations.
2. Group connections by unique `(src_ip, dest_ip, dest_port)` tuples.
3. Calculate the time delta ($\Delta t$) between consecutive packets for each unique tuple.
4. Compute the statistical variance and standard deviation of $\Delta t$.
5. Isolate external destinations where connection count exceeds 500 within a 24-hour window and standard deviation of the interval is $< 2.0$ seconds (indicating rigid automation).

## 3. Findings & Telemetry Evidence
Running the processing engine over the selected dataset isolated an anomaly matching the target hypothesis:

*   **Source Internal Host:** `192.168.10.45`
*   **Destination External Node:** `185.220.101[.]5` (Port `443`/TCP)
*   **Total Connection Count:** 2,840 calls over a 12-hour period.
*   **Calculated Heartbeat Window:** Mean $\Delta t$ = 15.02 seconds, Variance = 0.04 seconds.
*   **User-Agent Extracted (from HTTP/TLS SNI proxy logs):** `Mozilla/5.0 (Windows NT 10.0; Win64; x64)` but missing standard complementary browser telemetry requests, indicating an automated script wrapper mimicking a browser.

## 4. Operational Conclusion
*   **Status:** **Confirmed True Positive**.
*   **Handoff Vector:** The evidence has been packaged and escalated directly to the Incident Investigation Workflow as Case ID `CDL-INC-2026-08`.
