# Intrusion-detection-system
A Python-based signature and anomaly detection IDS

Simple Intrusion Detection System (IDS)
Description
This project is a Python-based Intrusion Detection System (IDS) designed to monitor network traffic and detect suspicious activities using both signature-based and anomaly-based detection techniques. The IDS captures real-time network packets using Scapy, analyzes flow-based features, and detects known attack patterns as well as anomalies using an Isolation Forest machine learning model.

Features: 

1. Packet capture of TCP/IP traffic on a specified network interface
2. Flow statistics and feature extraction: packet size, flow duration, packet and byte rates, TCP flags, window size
3. Signature-based detection of common suspicious patterns such as SYN flood and port scan
4. Anomaly-based detection trained dynamically on observed normal traffic, using Isolation Forest
5. Alerts logged with timestamps and threat details
6.ulti-threaded packet capturing for non-blocking analysis
7. Compatible with Windows (with installed Npcap) and Linux

Installation Prerequisites
1. Python 3.11 (64-bit recommended) installed and added to your system PATH
2. Npcap installed on Windows (install with WinPcap compatibility mode
3. Required Python libraries: scapy, numpy, scikit-learn

Steps
1. Install Python packages:

pip install scapy numpy scikit-learn

2. Install Npcap (Windows only):

Download from https://nmap.org/npcap/

3. Check "Install Npcap in WinPcap API-compatible Mode" during installation

How to Use
1. Open your terminal or command prompt as Administrator (required for packet sniffing)
2. Run the IDS script:

python main_ids.py

3. The IDS will:

a. Capture baseline traffic for about 30 seconds to train the anomaly detector.
b. Begin active detection of suspicious signatures and anomalies.
c. Log alerts in ids_alerts.log and print alerts in the console.

To stop the IDS, press Ctrl+C.

Design Decisions

1.Asynchronous Packet Capture: Uses a separate thread with Scapy's sniff() to avoid blocking the main detection logic.

2. Flow-Based Features: Tracks each network flow identified by source/destination IPs and ports to compute meaningful traffic statistics.

3. Signature Detection: Simple rules check TCP flag combinations and traffic rates to detect attacks like SYN flood and port scans.

4.Anomaly Detection: An Isolation Forest model dynamically trained on observed normal traffic features to find unusual patterns.

5.Logging: Alerts are logged with timestamps and severity levels for later analysis.

6.Cross-Platform Support: Designed to work on both Windows and Linux with minimal modifications.


Extending the IDS
1. Possible future improvements include:

2. Expanding the signature database to detect more attack patterns

3. Adding notifications via email or messaging services for critical alerts

4. Implementing a GUI dashboard for real-time monitoring

5. Supporting additional network protocols (UDP, ICMP) and payload inspection

6. Enhancing anomaly detection with more features or advanced ML models

7. Adding configuration files and command-line options for user flexibility

Troubleshooting
1. Packet capture requires admin/root privileges: Always run with elevated permissions.

2. Npcap missing or not in WinPcap mode: Packet sniffing will fail on Windows without this driver properly installed.

3. No alerts generated: Try generating test traffic such as port scans or SYN floods on your network to trigger detections.

4. Python or pip command not recognized: Ensure Python 3.11 installation folder and its Scripts subfolder are added to system PATH.


Acknowledgments: 

1.Based on tutorials and resources from FreeCodeCamp, Scapy documentation, and scikit-learn examples

2.Npcap team for the Windows packet capture driver

