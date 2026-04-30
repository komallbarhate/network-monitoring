"""
Packet Capture Engine using Scapy
Captures live network traffic and emits events via SocketIO
Falls back to simulation mode if Scapy/admin not available
"""
import threading
import time
import random
import logging
from collections import deque
from datetime import datetime

logger = logging.getLogger(__name__)

SCAPY_AVAILABLE = False
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
    conf.verb = 0
    SCAPY_AVAILABLE = True
    logger.info("[Capture] Scapy loaded successfully")
except Exception as e:
    logger.warning(f"[Capture] Scapy unavailable ({e}) – running in SIMULATION mode")


class PacketCapture:
    """
    Live packet capture with Scapy (falls back to simulation).
    Calls on_packet(pkt_info) for every captured packet.
    """

    def __init__(self, config, socketio=None, on_packet=None, on_threat=None):
        self.config = config
        self.socketio = socketio
        self.on_packet = on_packet
        self.on_threat = on_threat
        self.is_running = False
        self._thread = None
        self._packet_queue = deque(maxlen=config.MAX_PACKET_HISTORY)
        self._stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'other_packets': 0,
            'bytes_total': 0,
            'start_time': None,
        }
        self._lock = threading.Lock()
        self.simulation_mode = not SCAPY_AVAILABLE

    def start(self, interface=None):
        if self.is_running:
            return
        self.is_running = True
        self._stats['start_time'] = time.time()
        if self.simulation_mode:
            self._thread = threading.Thread(target=self._simulate_traffic, daemon=True)
        else:
            self._thread = threading.Thread(target=self._capture_live, args=(interface,), daemon=True)
        self._thread.start()

    def stop(self):
        self.is_running = False

    def _capture_live(self, interface):
        try:
            sniff(iface=interface, prn=self._process_scapy_packet, store=False,
                  stop_filter=lambda _: not self.is_running)
        except Exception as e:
            logger.error(f"[Capture] Live capture failed: {e} – switching to simulation")
            self.simulation_mode = True
            self._simulate_traffic()

    def _process_scapy_packet(self, packet):
        if not packet.haslayer(IP):
            return
        ip = packet[IP]
        pkt = {
            'timestamp': datetime.utcnow().isoformat(),
            'src_ip': ip.src, 'dst_ip': ip.dst,
            'src_port': None, 'dst_port': None,
            'protocol': 'OTHER', 'packet_size': len(packet), 'flags': '',
        }
        if packet.haslayer(TCP):
            t = packet[TCP]
            pkt.update(src_port=t.sport, dst_port=t.dport, protocol='TCP', flags=str(t.flags))
        elif packet.haslayer(UDP):
            u = packet[UDP]
            pkt.update(src_port=u.sport, dst_port=u.dport, protocol='UDP')
        elif packet.haslayer(ICMP):
            pkt['protocol'] = 'ICMP'
        self._handle_packet(pkt)

    def _simulate_traffic(self):
        internal = ['192.168.1.1', '192.168.1.10', '192.168.1.20', '10.0.0.1', '10.0.0.5']
        external = ['8.8.8.8', '1.1.1.1', '142.250.80.46', '151.101.1.69', '52.84.17.123']
        attack_ips = ['45.33.32.156', '185.220.101.1', '194.165.16.11']
        common_ports = [80, 443, 22, 21, 53, 3306, 8080, 8443, 25, 110, 143]
        scan_ports = list(range(1, 1024))

        attack_mode = None
        attack_countdown = random.randint(30, 60)
        scan_ip = None
        scan_idx = 0
        ddos_ip = None

        logger.info("[Simulation] Traffic simulation started")

        while self.is_running:
            attack_countdown -= 1
            if attack_countdown <= 0:
                scenario = random.choice(['port_scan', 'ddos', 'blacklist', 'normal', 'normal'])
                attack_countdown = random.randint(15, 40)
                if scenario == 'port_scan':
                    scan_ip = random.choice(attack_ips); scan_idx = 0; attack_mode = 'scan'
                elif scenario == 'ddos':
                    ddos_ip = random.choice(attack_ips); attack_mode = 'ddos'
                elif scenario == 'blacklist':
                    attack_mode = 'blacklist'
                else:
                    attack_mode = None

            if attack_mode == 'scan' and scan_idx < len(scan_ports):
                src_ip = scan_ip; dst_ip = random.choice(internal)
                dst_port = scan_ports[scan_idx]; scan_idx += 1
                proto = 'TCP'; flags = 'S'; size = 64; sleep = 0.04
            elif attack_mode == 'ddos' and ddos_ip:
                src_ip = ddos_ip; dst_ip = internal[0]
                dst_port = 80; proto = random.choice(['TCP', 'UDP'])
                flags = 'S' if proto == 'TCP' else ''; size = random.randint(64, 1500); sleep = 0.01
            elif attack_mode == 'blacklist':
                src_ip = '0.0.0.0'; dst_ip = random.choice(internal)
                dst_port = random.choice(common_ports); proto = 'TCP'
                flags = 'S'; size = 200; sleep = 0.2; attack_mode = None
            else:
                all_ips = internal + external
                src_ip = random.choice(all_ips); dst_ip = random.choice(all_ips)
                if src_ip == dst_ip: dst_ip = internal[0]
                dst_port = random.choice(common_ports)
                proto = random.choices(['TCP', 'UDP', 'ICMP'], weights=[60, 30, 10])[0]
                flags = random.choice(['S', 'SA', 'A', 'F', '']) if proto == 'TCP' else ''
                size = random.randint(64, 1500); sleep = random.uniform(0.06, 0.25)

            pkt = {
                'timestamp': datetime.utcnow().isoformat(),
                'src_ip': src_ip, 'dst_ip': dst_ip,
                'src_port': random.randint(1024, 65535), 'dst_port': dst_port,
                'protocol': proto, 'packet_size': size, 'flags': flags,
            }
            self._handle_packet(pkt)
            time.sleep(sleep)

    def _handle_packet(self, pkt):
        with self._lock:
            self._stats['total_packets'] += 1
            self._stats['bytes_total'] += pkt.get('packet_size', 0)
            p = pkt.get('protocol', 'OTHER')
            if p == 'TCP': self._stats['tcp_packets'] += 1
            elif p == 'UDP': self._stats['udp_packets'] += 1
            elif p == 'ICMP': self._stats['icmp_packets'] += 1
            else: self._stats['other_packets'] += 1
        self._packet_queue.append(pkt)
        if self.on_packet:
            self.on_packet(pkt)

    def get_recent_packets(self, n=50):
        packets = list(self._packet_queue)
        return packets[-n:]

    def get_stats(self):
        with self._lock:
            stats = dict(self._stats)
        elapsed = max(time.time() - (stats['start_time'] or time.time()), 0.001)
        stats['uptime_seconds'] = round(elapsed, 1)
        stats['pps'] = round(stats['total_packets'] / elapsed, 2)
        stats['mbps'] = round((stats['bytes_total'] * 8) / elapsed / 1_000_000, 4)
        stats['simulation_mode'] = self.simulation_mode
        return stats
