from scapy.all import sniff, TCP, UDP, ICMP


stats = {
    "packets": 0,
    "tcp": 0,
    "udp": 0,
    "icmp": 0
}


def process_packet(packet):
    stats["packets"] += 1

    if packet.haslayer(TCP):
        stats["tcp"] += 1

    elif packet.haslayer(UDP):
        stats["udp"] += 1

    elif packet.haslayer(ICMP):
        stats["icmp"] += 1

    print(packet.summary())


def start_capture():
    print("[+] ADAPTIVE-IDS started")
    print("[+] Listening on eth0...")
    print("[+] Press Ctrl+C to stop")

    sniff(
        iface="eth0",
        prn=process_packet,
        store=False
    )


if __name__ == "__main__":
    start_capture()