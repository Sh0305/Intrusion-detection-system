# Intrusion Detection System (IDS)

This project was developed during my cybersecurity internship to learn how Intrusion Detection Systems (IDS) work and how network traffic can be monitored for suspicious activities.

The system captures network packets, analyzes traffic patterns, applies detection rules, and generates alerts when potentially suspicious behavior is detected. Through this project, I gained practical exposure to network monitoring, packet analysis, and threat detection concepts.

## Features

- Captures and analyzes network traffic
- Detects suspicious activities using predefined rules
- Generates alerts for potential threats
- Monitors network traffic in real time
- Includes anomaly detection functionality
- Displays monitoring results through a simple interface

## Technologies Used

- Python
- Scapy
- Npcap
- Streamlit
- YAML
- NumPy
- Scikit-learn

## Project Structure

```text
app.py
alerts.py
packet_capture.py
traffic_analysis.py
detection_engine.py
intrusion.py
train_model.py
signatures.yaml
requirements.txt
README.md
```

## How It Works

1. Captures network packets from the selected network interface.
2. Extracts useful information from the packets.
3. Checks the traffic against predefined detection rules.
4. Analyzes traffic behavior for unusual patterns.
5. Generates alerts when suspicious activity is detected.
6. Displays the results for monitoring and analysis.

## Installation

Clone the repository:

```bash
git clone <repository-url>
cd intrusion-detection-system
```

Install the required libraries:

```bash
pip install -r requirements.txt
```

## Running the Project

```bash
python app.py
```

or

```bash
python intrusion.py
```

## Sample Detection Scenarios

The system can help identify:

- Port scanning attempts
- SYN flood-like behavior
- Suspicious network traffic patterns
- Unusual traffic activity
- Potential threats based on configured detection rules

## What I Learned

While working on this project, I learned about:

- Network traffic analysis
- Packet capturing and inspection
- Intrusion Detection System (IDS) concepts
- Threat detection techniques
- Security monitoring workflows
- Alert generation mechanisms
- Python libraries used in cybersecurity

## My Role

During my internship, I worked on understanding how IDS solutions monitor network traffic and identify suspicious activities. This project helped me explore network security concepts, traffic analysis techniques, and different approaches used for threat detection and alert generation.

## Future Improvements

- Add more attack detection rules
- Improve detection accuracy
- Enhance reporting features
- Add support for more network protocols
- Improve visualization of alerts and traffic statistics

## Disclaimer

This project was developed for educational and learning purposes during a cybersecurity internship. It should only be used in authorized environments and for ethical security testing.
