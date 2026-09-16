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
# Detection Configuration
# =========================

# TCP SYN Port Scan
PORT_SCAN_THRESHOLD = 10
PORT_SCAN_WINDOW = 5
PORT_SCAN_COOLDOWN = 5

# UDP Scan
UDP_SCAN_THRESHOLD = 10
UDP_SCAN_WINDOW = 5
UDP_SCAN_COOLDOWN = 5

# ICMP Flood
ICMP_FLOOD_THRESHOLD = 20
ICMP_FLOOD_WINDOW = 5
ICMP_FLOOD_COOLDOWN = 5

# TCP SYN Flood
SYN_FLOOD_THRESHOLD = 20
SYN_FLOOD_WINDOW = 5
SYN_FLOOD_COOLDOWN = 5


# =========================
# Detection Trackers
# =========================

port_scan_tracker = defaultdict(list)
port_scan_last_alert = {}

udp_scan_tracker = defaultdict(list)
udp_scan_last_alert = {}

icmp_flood_tracker = defaultdict(list)
icmp_flood_last_alert = {}

syn_flood_tracker = defaultdict(list)
syn_flood_last_alert = {}


# =========================
# Alert Helper
# =========================

def create_alert(severity, alert_type, source, description):

    alert_time = datetime.now().strftime("%H:%M:%S")

    alert = {
        "time": alert_time,
        "severity": severity,
        "type": alert_type,
        "source": source,
        "description": description
    }

    alerts.append(alert)

    print(
        f"[!] {alert_type.upper()} DETECTED | "
        f"Source: {source} | "
        f"{description}"
    )


# =========================
# TCP SYN Port Scan
# =========================

def detect_port_scan(packet):

    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return

    tcp_flags = packet[TCP].flags

    # SYN without ACK = initial TCP connection attempt
    if tcp_flags & 0x02 and not tcp_flags & 0x10:

        source_ip = packet[IP].src
        destination_port = packet[TCP].dport
        current_time = time.time()

        port_scan_tracker[source_ip].append(
            (current_time, destination_port)
        )

        # Remove old entries
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

            last_alert_time = port_scan_last_alert.get(
                source_ip,
                0
            )

            if current_time - last_alert_time >= PORT_SCAN_COOLDOWN:

                create_alert(
                    "HIGH",
                    "Port Scan",
                    source_ip,
                    (
                        f"TCP SYN scan detected across "
                        f"{len(unique_ports)} ports"
                    )
                )

                port_scan_last_alert[source_ip] = current_time

            # Reset after a detection attempt
            port_scan_tracker[source_ip].clear()


# =========================
# UDP Scan
# =========================

def detect_udp_scan(packet):

    if not packet.haslayer(IP) or not packet.haslayer(UDP):
        return

    source_ip = packet[IP].src
    destination_port = packet[UDP].dport
    current_time = time.time()

    udp_scan_tracker[source_ip].append(
        (current_time, destination_port)
    )

    # Remove old entries
    udp_scan_tracker[source_ip] = [
        entry
        for entry in udp_scan_tracker[source_ip]
        if current_time - entry[0] <= UDP_SCAN_WINDOW
    ]

    unique_ports = {
        port
        for _, port in udp_scan_tracker[source_ip]
    }

    if len(unique_ports) >= UDP_SCAN_THRESHOLD:

        last_alert_time = udp_scan_last_alert.get(
            source_ip,
            0
        )

        if current_time - last_alert_time >= UDP_SCAN_COOLDOWN:

            create_alert(
                "HIGH",
                "UDP Scan",
                source_ip,
                (
                    f"UDP scan detected across "
                    f"{len(unique_ports)} ports"
                )
            )

            udp_scan_last_alert[source_ip] = current_time

        udp_scan_tracker[source_ip].clear()


# =========================
# ICMP Flood
# =========================

def detect_icmp_flood(packet):

    if not packet.haslayer(IP) or not packet.haslayer(ICMP):
        return

    source_ip = packet[IP].src
    current_time = time.time()

    icmp_flood_tracker[source_ip].append(
        current_time
    )

    # Remove old entries
    icmp_flood_tracker[source_ip] = [
        packet_time
        for packet_time in icmp_flood_tracker[source_ip]
        if current_time - packet_time <= ICMP_FLOOD_WINDOW
    ]

    packet_count = len(
        icmp_flood_tracker[source_ip]
    )

    if packet_count >= ICMP_FLOOD_THRESHOLD:

        last_alert_time = icmp_flood_last_alert.get(
            source_ip,
            0
        )

        if current_time - last_alert_time >= ICMP_FLOOD_COOLDOWN:

            create_alert(
                "HIGH",
                "ICMP Flood",
                source_ip,
                (
                    f"Excessive ICMP traffic detected: "
                    f"{packet_count} packets in "
                    f"{ICMP_FLOOD_WINDOW} seconds"
                )
            )

            icmp_flood_last_alert[source_ip] = current_time

        icmp_flood_tracker[source_ip].clear()


# =========================
# TCP SYN Flood
# =========================

def detect_syn_flood(packet):

    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return

    tcp_flags = packet[TCP].flags

    # SYN without ACK
    if tcp_flags & 0x02 and not tcp_flags & 0x10:

        source_ip = packet[IP].src
        current_time = time.time()

        syn_flood_tracker[source_ip].append(
            current_time
        )

        # Remove old entries
        syn_flood_tracker[source_ip] = [
            packet_time
            for packet_time in syn_flood_tracker[source_ip]
            if current_time - packet_time <= SYN_FLOOD_WINDOW
        ]

        packet_count = len(
            syn_flood_tracker[source_ip]
        )

        if packet_count >= SYN_FLOOD_THRESHOLD:

            last_alert_time = syn_flood_last_alert.get(
                source_ip,
                0
            )

            if current_time - last_alert_time >= SYN_FLOOD_COOLDOWN:

                create_alert(
                    "HIGH",
                    "TCP SYN Flood",
                    source_ip,
                    (
                        f"Excessive TCP SYN traffic detected: "
                        f"{packet_count} SYN packets in "
                        f"{SYN_FLOOD_WINDOW} seconds"
                    )
                )

                syn_flood_last_alert[source_ip] = current_time

            syn_flood_tracker[source_ip].clear()


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
        detect_syn_flood(packet)

    # UDP
    elif packet.haslayer(UDP):

        stats["udp"] += 1
        protocol = "UDP"

        info = (
            f"{packet[UDP].sport} → "
            f"{packet[UDP].dport}"
        )

        detect_udp_scan(packet)

    # ICMP
    elif packet.haslayer(ICMP):

        stats["icmp"] += 1
        protocol = "ICMP"

        info = "ICMP packet"

        detect_icmp_flood(packet)

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
    print("[+] Detection rules enabled:")
    print("    - TCP SYN Port Scan")
    print("    - UDP Scan")
    print("    - ICMP Flood")
    print("    - TCP SYN Flood")
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