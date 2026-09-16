from collections import deque, defaultdict
from datetime import datetime
import time

from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP


# =========================
# Network Interface
# =========================

INTERFACE = "eth1"


# =========================
# Traffic Statistics
# =========================

stats = {
    "packets": 0,
    "tcp": 0,
    "udp": 0,
    "icmp": 0,
    "arp": 0,
    "other": 0
}


# =========================
# Recent Packets & Alerts
# =========================

recent_packets = deque(maxlen=50)
alerts = deque(maxlen=50)


# =========================
# Port Scan Detection
# =========================

port_scan_tracker = defaultdict(list)

PORT_SCAN_THRESHOLD = 10
PORT_SCAN_WINDOW = 5


def detect_port_scan(packet):
    """
    Detect multiple TCP SYN packets from the same source
    targeting different destination ports within a short time.
    """

    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return

    tcp_flags = packet[TCP].flags

    # TCP SYN without ACK = initial connection attempt
    if tcp_flags & 0x02 and not tcp_flags & 0x10:

        source_ip = packet[IP].src
        destination_port = packet[TCP].dport

        current_time = time.time()

        port_scan_tracker[source_ip].append(
            (current_time, destination_port)
        )

        # Keep only packets inside the detection window
        port_scan_tracker[source_ip] = [
            entry
            for entry in port_scan_tracker[source_ip]
            if current_time - entry[0] <= PORT_SCAN_WINDOW
        ]

        unique_ports = {
            port
            for _, port in port_scan_tracker[source_ip]
        }

        if len(unique_ports) >= PORT_SCAN_THRESHOLD:

            alert_time = datetime.now().strftime("%H:%M:%S")

            alerts.append({
                "time": alert_time,
                "severity": "HIGH",
                "type": "Port Scan",
                "source": source_ip,
                "description": (
                    f"TCP SYN scan detected across "
                    f"{len(unique_ports)} ports"
                )
            })

            print(
                f"[!] PORT SCAN DETECTED | "
                f"Source: {source_ip} | "
                f"Ports: {len(unique_ports)}"
            )

            port_scan_tracker[source_ip].clear()


# =========================
# Packet Processing
# =========================

def process_packet(packet):

    stats["packets"] += 1

    protocol = "OTHER"
    source = "-"
    destination = "-"
    info = packet.summary()

    timestamp = datetime.now().strftime("%H:%M:%S")

    # IP addresses
    if packet.haslayer(IP):
        source = packet[IP].src
        destination = packet[IP].dst

    # TCP
    if packet.haslayer(TCP):

        stats["tcp"] += 1
        protocol = "TCP"

        info = (
            f"{packet[TCP].sport} → "
            f"{packet[TCP].dport}"
        )

        detect_port_scan(packet)

    # UDP
    elif packet.haslayer(UDP):

        stats["udp"] += 1
        protocol = "UDP"

        info = (
            f"{packet[UDP].sport} → "
            f"{packet[UDP].dport}"
        )

    # ICMP
    elif packet.haslayer(ICMP):

        stats["icmp"] += 1
        protocol = "ICMP"
        info = "ICMP packet"

    # ARP
    elif packet.haslayer(ARP):

        stats["arp"] += 1
        protocol = "ARP"

        source = packet[ARP].psrc
        destination = packet[ARP].pdst

        info = "ARP request/reply"

    # Other
    else:

        stats["other"] += 1

    recent_packets.append({
        "time": timestamp,
        "protocol": protocol,
        "source": source,
        "destination": destination,
        "info": info
    })


# =========================
# Start Packet Capture
# =========================

def start_capture():

    print("[+] ADAPTIVE-IDS started")
    print(f"[+] Listening on {INTERFACE}...")
    print("[+] Dashboard: http://127.0.0.1:5000")
    print("[+] Port-scan detection enabled")
    print("[+] Press Ctrl+C to stop")

    sniff(
        iface=INTERFACE,
        prn=process_packet,
        store=False
    )


# =========================
# Run Directly
# =========================

if __name__ == "__main__":
    start_capture()