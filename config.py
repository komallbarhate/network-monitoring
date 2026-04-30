import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'netmon-secret-key-2024-indigenous')
    SQLALCHEMY_DATABASE_URI = 'sqlite:///netmon.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Threat detection thresholds
    PORT_SCAN_THRESHOLD = 15        # packets to same destination, different ports
    DDOS_THRESHOLD = 500            # packets per second from single IP
    UNKNOWN_IP_THRESHOLD = 100      # packets from unknown/new IP
    ANOMALY_SCORE_THRESHOLD = 0.7   # ML anomaly score
    
    # Severity levels
    SEVERITY_LOW = "LOW"
    SEVERITY_MEDIUM = "MEDIUM"
    SEVERITY_HIGH = "HIGH"
    SEVERITY_CRITICAL = "CRITICAL"
    
    # Network interface (None = auto-detect)
    INTERFACE = None
    
    # Max packets stored in memory
    MAX_PACKET_HISTORY = 10000
    
    # Blacklisted IPs (can be extended via admin panel)
    DEFAULT_BLACKLIST = [
        "0.0.0.0",
    ]
