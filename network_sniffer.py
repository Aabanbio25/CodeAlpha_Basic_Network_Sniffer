#!/usr/bin/env python3
import sys
from datetime import datetime
from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, Raw, sniff

PROTOCOL_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}


def format_payload(data):
  try:
    text = data.decode("utf-8", errors="replace")
    clean_text = "".join([c if 32 <= ord(c) <= 126 else "." for c in text])
    return clean_text[:80] + ("..." if len(clean_text) > 80 else "")
  except Exception:
    return data.hex()[:80] + ("..." if len(data.hex()) > 80 else "")


def process_packet(packet):
  timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

  if packet.haslayer(IP):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto_num = packet[IP].proto
    proto_name = PROTOCOL_MAP.get(proto_num, f"Other({proto_num})")
    pkt_len = len(packet)

    src_port = ""
    dst_port = ""

    if packet.haslayer(TCP):
      src_port = f":{packet[TCP].sport}"
      dst_port = f":{packet[TCP].dport}"
    elif packet.haslayer(UDP):
      src_port = f":{packet[UDP].sport}"
      dst_port = f":{packet[UDP].dport}"

    print(
        f"[{timestamp}] [{proto_name:<5}] {src_ip}{src_port} ->"
        f" {dst_ip}{dst_port} | Size: {pkt_len} bytes"
    )

    if packet.haslayer(Raw):
      payload = packet[Raw].load
      print(f"    └── Payload: {format_payload(payload)}")

  elif packet.haslayer(ARP):
    src_mac = packet[ARP].hwsrc
    src_ip = packet[ARP].psrc
    dst_ip = packet[ARP].pdst
    op = "Request" if packet[ARP].op == 1 else "Reply"
    print(
        f"[{timestamp}] [ARP  ] Op: {op:<7} | {src_ip} ({src_mac}) -> {dst_ip}"
    )


def main():
  print("=" * 70)
  print("       CODEALPHA - BASIC NETWORK SNIFFER       ")
  print("=" * 70)
  print("[*] Starting Packet Capture...")
  print("[*] Press Ctrl+C to stop sniffing.\n")

  try:
    sniff(prn=process_packet, store=False)
  except KeyboardInterrupt:
    print("\n\n[*] Sniffer stopped by user.")
    sys.exit(0)
  except PermissionError:
    print(
        "\n[!] Error: Administrative / Root privileges required to capture"
        " packets."
    )
    sys.exit(1)


if __name__ == "__main__":
  main()