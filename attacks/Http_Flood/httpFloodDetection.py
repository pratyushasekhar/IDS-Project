from scapy.all import sniff
from scapy.layers.inet import IP, TCP
import time

request_times = {}
returnString = ""

TARGET_PORT = 5000
THRESHOLD = 3
WINDOW = 3

def detect_HTTP_Flood(packet):
    global returnString

    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return False

    if packet[TCP].dport != TARGET_PORT:
        return False

    src = packet[IP].src
    now = time.time()

    request_times.setdefault(src, [])
    request_times[src].append(now)
    request_times[src] = [t for t in request_times[src] if now - t <= WINDOW]

    count = len(request_times[src])
    print(f"[HTTP FLOOD DEBUG] {src} count={count}", flush=True)

    if count >= THRESHOLD:
        returnString = f"HTTP Flood attack detected from {src}"
        print("[HTTP FLOOD DETECTED]", returnString, flush=True)
        return True

    return False

def detectMain(iface, return_dict):
    print(f"Detecting HTTP Flood on {iface}...", flush=True)
    sniff(
        iface=iface,
        lfilter=lambda p: p.haslayer(IP) and p.haslayer(TCP),
        stop_filter=detect_HTTP_Flood,
        store=False
    )
    return_dict[0] = returnString
