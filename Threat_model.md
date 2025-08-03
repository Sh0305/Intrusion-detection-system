## Threat Modeling for IDS

### Assets
- Real-time network traffic
- Detection logs and alerts
- IDS configuration and codebase
- Host server security

### System Architecture
- Packet capture component (Scapy + Npcap)
- Traffic analysis & detection engine (Python modules)
- Logging/alerting (log files)
- Optional: Web interface or remote access

### Threat Actors
- External attackers on the network
- Malicious insiders with host access
- Accidental misconfigurations

### Main Threats and Risks

| Threat            | Likelihood | Impact | Mitigation                          |
|-------------------|------------|--------|-------------------------------------|
| IDS evasion       | Medium     | High   | Use signature+anomaly detection     |
| DoS/flood         | High       | Medium | Throttle analysis, alert on DoS     |
| Log tampering     | Low        | High   | Secure log permissions, backups     |
| Data disclosure   | Medium     | High   | Restrict access to logs             |

### Controls and Mitigation Plan
- Run IDS with minimal privileges, not as root/admin.
- Protect logs with permissions.
- Monitor IDS performance and alert if overloaded.
- Regularly patch/update Python, dependencies, and OS.

### Review
- Review threat list with each significant IDS code change or deployment.
