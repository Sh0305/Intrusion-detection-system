from scapy.all import sniff, IP, TCP
from collections import defaultdict
import threading
import queue
from sklearn.ensemble import IsolationForest
import numpy as np
import logging
import json
from datetime import datetime

#capturing packets(packet capture.py)
class PacketCapture:
    def __init__(self):
        self.packet_queue = queue.Queue()
        self.stop_capture = threading.Event()

    def packet_callback(self, packet):
        # Only capture IP/TCP packets
        if IP in packet and TCP in packet:
            self.packet_queue.put(packet)

    def start_capture(self, interface=None):
        def capture_thread():
            sniff(iface=interface,
                  prn=self.packet_callback,
                  store=0,
                  stop_filter=lambda _: self.stop_capture.is_set())

        self.capture_thread = threading.Thread(target=capture_thread, daemon=True)
        self.capture_thread.start()

    def stop(self):
        self.stop_capture.set()
        self.capture_thread.join()

#Analyzing packets (traffic analysis.py)
class TrafficAnalyzer:
    def __init__(self):
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None
        })

    def analyze_packet(self, packet):
        if IP in packet and TCP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport

            flow_key = (ip_src, ip_dst, port_src, port_dst)

            # Update flow statistics
            stats = self.flow_stats[flow_key]
            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)
            current_time = packet.time

            if not stats['start_time']:
                stats['start_time'] = current_time
            stats['last_time'] = current_time

            return self.extract_features(packet, stats)

    def extract_features(self, packet, stats):
        duration = stats['last_time'] - stats['start_time']
        # Avoid division by zero
        duration = duration if duration > 0 else 1e-6

        tcp_flags = packet[TCP].flags

        # Convert flags to integer for comparisons
        if hasattr(tcp_flags, 'value'):
            flags_val = tcp_flags.value
        else:
            flags_val = int(tcp_flags)

        return {
            'packet_size': len(packet),
            'flow_duration': duration,
            'packet_rate': stats['packet_count'] / duration,
            'byte_rate': stats['byte_count'] / duration,
            'tcp_flags': flags_val,
            'window_size': packet[TCP].window
        }

#implementing signature and anomaly based detection (hybrid.py)
class DetectionEngine:
    def __init__(self):
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        self.signature_rules = self.load_signature_rules()
        self.training_data = []
        self.is_trained = False

    def load_signature_rules(self):
        return {
            'syn_flood': {
                # SYN flag is 0x02
                'condition': lambda features: (
                    features['tcp_flags'] & 0x02 == 0x02 and  # SYN flag set
                    features['packet_rate'] > 100
                )
            },
            'port_scan': {
                'condition': lambda features: (
                    features['packet_size'] < 100 and
                    features['packet_rate'] > 50
                )
            }
        }

    def train_anomaly_detector(self, normal_traffic_data):
        # normal_traffic_data should be a 2D numpy array or list of feature vectors:
        # Use packet_size, packet_rate, byte_rate as features
        if len(normal_traffic_data) > 0:
            X = np.array(normal_traffic_data)
            self.anomaly_detector.fit(X)
            self.is_trained = True
        else:
            print("Warning: No normal traffic data provided for training")

    def detect_threats(self, features):
        threats = []

        # Signature-based detection
        for rule_name, rule in self.signature_rules.items():
            if rule['condition'](features):
                threats.append({
                    'type': 'signature',
                    'rule': rule_name,
                    'confidence': 1.0
                })

        # Anomaly-based detection if trained
        if self.is_trained:
            feature_vector = np.array([[features['packet_size'],
                                        features['packet_rate'],
                                        features['byte_rate']]])
            anomaly_score = self.anomaly_detector.score_samples(feature_vector)[0]
            if anomaly_score < -0.5:  # Threshold for anomaly detection
                threats.append({
                    'type': 'anomaly',
                    'score': anomaly_score,
                    'confidence': min(1.0, abs(anomaly_score))
                })
        else:
            # You can log or print here that anomaly detection is not trained yet
            pass

        return threats

#Alert loggging mechanism (alert.py)
class AlertSystem:
    def __init__(self, log_file="ids_alerts.log"):
        self.logger = logging.getLogger("IDS_Alerts")
        self.logger.setLevel(logging.INFO)

        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        if not self.logger.hasHandlers():
            self.logger.addHandler(handler)

    def generate_alert(self, threat, packet_info):
        alert = {
            'timestamp': datetime.now().isoformat(),
            'threat_type': threat['type'],
            'source_ip': packet_info.get('source_ip'),
            'destination_ip': packet_info.get('destination_ip'),
            'confidence': threat.get('confidence', 0.0),
            'details': threat
        }

        self.logger.warning(json.dumps(alert))

        if threat.get('confidence', 0) > 0.8:
            self.logger.critical(
                f"High confidence threat detected: {json.dumps(alert)}"
            )
            # Add notification actions here (email, webhook, etc.)


#the main execution class(intrusion.py)
class IntrusionDetectionSystem:
    def __init__(self, interface=None):
        self.packet_capture = PacketCapture()
        self.traffic_analyzer = TrafficAnalyzer()
        self.detection_engine = DetectionEngine()
        self.alert_system = AlertSystem()
        self.interface = interface

    def collect_training_data(self, duration=30):
        print(f"[INFO] Collecting normal traffic data for training (approx {duration} seconds)...")
        training_packets = []
        start_time = datetime.now()
        while (datetime.now() - start_time).seconds < duration:
            try:
                packet = self.packet_capture.packet_queue.get(timeout=1)
                features = self.traffic_analyzer.analyze_packet(packet)
                if features:
                    training_packets.append([
                        features['packet_size'],
                        features['packet_rate'],
                        features['byte_rate']
                    ])
            except queue.Empty:
                continue
        print(f"[INFO] Collected {len(training_packets)} training samples.")
        return training_packets

    def start(self):
        print(f"Starting IDS on interface {self.interface or 'default'}")
        self.packet_capture.start_capture(self.interface)

        # Collect normal traffic data first for training anomaly detector
        normal_traffic = self.collect_training_data(duration=30)
        self.detection_engine.train_anomaly_detector(normal_traffic)
        print("[INFO] Anomaly detector trained with collected normal traffic data.")

        try:
            while True:
                try:
                    packet = self.packet_capture.packet_queue.get(timeout=1)
                    features = self.traffic_analyzer.analyze_packet(packet)

                    if features:
                        threats = self.detection_engine.detect_threats(features)

                        for threat in threats:
                            packet_info = {
                                'source_ip': packet[IP].src,
                                'destination_ip': packet[IP].dst,
                                'source_port': packet[TCP].sport,
                                'destination_port': packet[TCP].dport
                            }
                            self.alert_system.generate_alert(threat, packet_info)

                except queue.Empty:
                    continue
        except KeyboardInterrupt:
            print("\nStopping IDS...")
            self.packet_capture.stop()


if __name__ == "__main__":
    # Replace with your actual interface name or None for default
    # For Windows, e.g., interface="Wi-Fi" or interface="Ethernet"
    iface_name = None

    ids = IntrusionDetectionSystem(interface=iface_name)
    ids.start()
