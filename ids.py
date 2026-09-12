from collections import deque
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP


stats = {
    "packets": 0,
    "tcp": 0,
    "udp": 0,
    "icmp": 0,
    "arp": 0,
    "other": 0
}

recent_packets = deque(maxlen=50)


def process_packet(packet):
    stats["packets"] += 1

    protocol = "OTHER"
    source = "-"
    destination = "-"
    info = packet.summary()

    timestamp = datetime.now().strftime("%H:%M:%S")

    if packet.haslayer(IP):
        source = packet[IP].src
        destination = packet[IP].dst

    if packet.haslayer(TCP):
        stats["tcp"] += 1
        protocol = "TCP"
        info = f"{packet[TCP].sport} → {packet[TCP].dport}"

    elif packet.haslayer(UDP):
        stats["udp"] += 1
        protocol = "UDP"
        info = f"{packet[UDP].sport} → {packet[UDP].dport}"

    elif packet.haslayer(ICMP):
        stats["icmp"] += 1
        protocol = "ICMP"
        info = "ICMP packet"

    elif packet.haslayer(ARP):
        stats["arp"] += 1
        protocol = "ARP"
        source = packet[ARP].psrc
        destination = packet[ARP].pdst
        info = "ARP request/reply"

    else:
        stats["other"] += 1

    recent_packets.append({
        "time": timestamp,
        "protocol": protocol,
        "source": source,
        "destination": destination,
        "info": info
    })


def start_capture():
    print("[+] ADAPTIVE-IDS started")
    print("[+] Listening on eth0...")
    print("[+] Dashboard: http://127.0.0.1:5000")
    print("[+] Press Ctrl+C to stop")

    sniff(
        iface="eth0",
        prn=process_packet,
        store=False
    )


if __name__ == "__main__":
    start_capture()