from scapy.all import sniff


def process_packet(packet):
    print(packet.summary())


print("[+] ADAPTIVE-IDS started")
print("[+] Listening on eth0...")
print("[+] Press Ctrl+C to stop")

sniff(iface="eth0", prn=process_packet, store=False)
