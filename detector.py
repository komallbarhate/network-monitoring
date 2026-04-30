"""
AI/ML Anomaly Detection Engine for NetMon
Uses Isolation Forest for unsupervised anomaly detection
"""
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from collections import defaultdict, deque
import threading
import time
import logging

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """
    ML-based anomaly detector using Isolation Forest.
    Learns normal traffic patterns and flags deviations.
    """

    def __init__(self, contamination=0.1, window_size=500):
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=100,
            random_state=42,
            warm_start=False
        )
        self.scaler = StandardScaler()
        self.window_size = window_size
        self.feature_buffer = deque(maxlen=window_size)
        self.is_trained = False
        self.training_lock = threading.Lock()
        self.min_train_samples = 50
        self._retrain_interval = 300  # retrain every 5 minutes
        self._last_trained = 0
        self._anomaly_scores = deque(maxlen=1000)

    def extract_features(self, packet_info: dict) -> list:
        """
        Extract numerical features from a packet for ML processing.
        Features: [packet_size, src_port, dst_port, protocol_num, hour_of_day, is_tcp, is_udp, is_icmp]
        """
        proto_map = {'TCP': 6, 'UDP': 17, 'ICMP': 1, 'OTHER': 0}
        protocol = packet_info.get('protocol', 'OTHER')
        proto_num = proto_map.get(protocol, 0)

        features = [
            float(packet_info.get('packet_size', 0)),
            float(packet_info.get('src_port', 0) or 0),
            float(packet_info.get('dst_port', 0) or 0),
            float(proto_num),
            float(time.localtime().tm_hour),
            1.0 if protocol == 'TCP' else 0.0,
            1.0 if protocol == 'UDP' else 0.0,
            1.0 if protocol == 'ICMP' else 0.0,
        ]
        return features

    def add_packet(self, packet_info: dict):
        """Add a packet's features to the training buffer."""
        features = self.extract_features(packet_info)
        self.feature_buffer.append(features)

        # Auto-retrain periodically
        now = time.time()
        if (len(self.feature_buffer) >= self.min_train_samples and
                now - self._last_trained > self._retrain_interval):
            threading.Thread(target=self._train, daemon=True).start()

    def _train(self):
        """Train the Isolation Forest model on buffered data."""
        with self.training_lock:
            if len(self.feature_buffer) < self.min_train_samples:
                return
            try:
                data = np.array(list(self.feature_buffer))
                data_scaled = self.scaler.fit_transform(data)
                self.model.fit(data_scaled)
                self.is_trained = True
                self._last_trained = time.time()
                logger.info(f"[AI] Model retrained on {len(data)} samples")
            except Exception as e:
                logger.error(f"[AI] Training error: {e}")

    def predict(self, packet_info: dict) -> dict:
        """
        Predict if a packet is anomalous.
        Returns dict with: is_anomaly, anomaly_score, confidence
        """
        if not self.is_trained:
            return {'is_anomaly': False, 'anomaly_score': 0.0, 'confidence': 0.0}

        try:
            features = self.extract_features(packet_info)
            data = np.array([features])
            data_scaled = self.scaler.transform(data)

            prediction = self.model.predict(data_scaled)[0]  # -1 = anomaly, 1 = normal
            score = self.model.score_samples(data_scaled)[0]  # lower = more anomalous

            # Normalize score to 0-1 (1 = most anomalous)
            normalized_score = max(0.0, min(1.0, (score + 0.5) * -1 + 0.5))
            is_anomaly = prediction == -1

            self._anomaly_scores.append(normalized_score)

            return {
                'is_anomaly': is_anomaly,
                'anomaly_score': round(normalized_score, 4),
                'confidence': round(abs(score), 4),
                'raw_score': round(float(score), 4)
            }
        except Exception as e:
            logger.error(f"[AI] Prediction error: {e}")
            return {'is_anomaly': False, 'anomaly_score': 0.0, 'confidence': 0.0}

    def get_stats(self) -> dict:
        """Return detector statistics."""
        scores = list(self._anomaly_scores)
        return {
            'is_trained': self.is_trained,
            'buffer_size': len(self.feature_buffer),
            'min_train_samples': self.min_train_samples,
            'avg_anomaly_score': round(np.mean(scores), 4) if scores else 0.0,
            'anomaly_rate': round(sum(1 for s in scores if s > 0.5) / len(scores), 4) if scores else 0.0,
            'last_trained': self._last_trained
        }

    def force_train(self):
        """Force immediate model training."""
        self._last_trained = 0
        self._train()
        return self.is_trained


class RuleBasedDetector:
    """
    Rule-based threat detector for known attack patterns:
    - Port scanning
    - DDoS-like traffic
    - Blacklisted IPs
    """

    def __init__(self, config):
        self.config = config
        self.ip_port_tracker = defaultdict(set)       # src_ip -> set of dst_ports
        self.ip_packet_counter = defaultdict(list)    # src_ip -> [timestamps]
        self.ip_first_seen = {}                       # ip -> timestamp
        self.blacklist = set(config.DEFAULT_BLACKLIST)
        self._lock = threading.Lock()
        self._cleanup_interval = 60
        threading.Thread(target=self._periodic_cleanup, daemon=True).start()

    def update_blacklist(self, ip_set: set):
        """Update the in-memory blacklist."""
        with self._lock:
            self.blacklist = ip_set

    def analyze(self, packet_info: dict) -> list:
        """
        Analyze a packet for threats. Returns list of threat dicts.
        Each threat: {type, severity, description, source_ip, destination_ip}
        """
        threats = []
        src_ip = packet_info.get('src_ip', '')
        dst_ip = packet_info.get('dst_ip', '')
        dst_port = packet_info.get('dst_port', 0) or 0
        now = time.time()

        if not src_ip:
            return threats

        with self._lock:
            # 1. Blacklist check
            if src_ip in self.blacklist:
                threats.append({
                    'type': 'blacklisted_ip',
                    'severity': 'CRITICAL',
                    'description': f'Traffic from blacklisted IP: {src_ip}',
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                })

            # 2. Port scan detection
            if dst_port:
                self.ip_port_tracker[src_ip].add(dst_port)
                unique_ports = len(self.ip_port_tracker[src_ip])
                if unique_ports > self.config.PORT_SCAN_THRESHOLD:
                    threats.append({
                        'type': 'port_scan',
                        'severity': 'HIGH',
                        'description': f'Port scanning detected: {src_ip} scanned {unique_ports} ports',
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                    })

            # 3. DDoS-like traffic detection (high packet rate)
            self.ip_packet_counter[src_ip].append(now)
            # Keep only last 5 seconds
            self.ip_packet_counter[src_ip] = [
                t for t in self.ip_packet_counter[src_ip] if now - t <= 5
            ]
            pps = len(self.ip_packet_counter[src_ip]) / 5.0
            if pps > self.config.DDOS_THRESHOLD / 60:  # scaled per second
                severity = 'CRITICAL' if pps > self.config.DDOS_THRESHOLD else 'HIGH'
                threats.append({
                    'type': 'ddos',
                    'severity': severity,
                    'description': f'DDoS-like traffic from {src_ip}: {pps:.1f} pkt/s',
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                })

            # 4. New/unknown IP tracking
            if src_ip not in self.ip_first_seen:
                self.ip_first_seen[src_ip] = now
                if len(self.ip_first_seen) > 10:  # Only after some baseline
                    threats.append({
                        'type': 'unknown_ip',
                        'severity': 'LOW',
                        'description': f'First contact from new IP: {src_ip}',
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                    })

        return threats

    def get_top_talkers(self, n=10) -> list:
        """Return top IPs by packet count."""
        with self._lock:
            counts = {ip: len(ts) for ip, ts in self.ip_packet_counter.items()}
            return sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n]

    def reset_ip_tracker(self, ip: str):
        """Reset tracking for a specific IP (e.g., after whitelisting)."""
        with self._lock:
            self.ip_port_tracker.pop(ip, None)
            self.ip_packet_counter.pop(ip, None)

    def _periodic_cleanup(self):
        """Periodically clean stale port scan data."""
        while True:
            time.sleep(self._cleanup_interval)
            with self._lock:
                # Reset port scanner after 1 min (sliding window)
                self.ip_port_tracker.clear()
                # Keep first_seen for history
