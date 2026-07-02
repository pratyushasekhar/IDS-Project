
from scapy.all import sniff
from scapy.layers.inet import IP, TCP
import time

connections = {}
returnString = ""

TARGET_PORT = 5000
MIN_CONNECTIONS = 20
TIMEOUT = 15


def cleanup():
    now = time.time()

    remove = []

    for key, value in connections.items():
        if now - value["last_seen"] > TIMEOUT:
            remove.append(key)

    for key in remove:
        del connections[key]


def detect(packet):
    global returnString

    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return False

    ip = packet[IP]
    tcp = packet[TCP]

    if tcp.dport != TARGET_PORT:
        return False

    cleanup()

    key = (ip.src, tcp.sport)

    now = time.time()

    if key not in connections:
        connections[key] = {
            "start": now,
            "last_seen": now
        }
    else:
        connections[key]["last_seen"] = now

    #
    # Remove connections that close normally
    #
    if tcp.flags & 0x01 or tcp.flags & 0x04:
        if key in connections:
            del connections[key]
        return False

    active = sum(
        1
        for (src, _), info in connections.items()
        if src == ip.src
    )

    print(f"{ip.src} active connections: {active}")

    if active >= MIN_CONNECTIONS:
        returnString = f"Slowloris attack detected from {ip.src}"
        return True

    return False


def incoming_filter(packet):
    return packet.haslayer(IP) and packet.haslayer(TCP)


def detectMain(iface, return_dict):

    print("Detecting Slowloris...")

    sniff(
        iface=iface,
        lfilter=incoming_filter,
        stop_filter=detect,
        store=False
    )

    return_dict[0] = returnString


"""rom scapy.all import *
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import *
import time

request_times = {}

returnString = ""

def detect_slowloris(packet):
    print(".")

    global request_times
    global returnString

    #==Changeable Params==
    timeout_threshold = 3
    howManyValidFields = 5
    #=====================

    cur_time = time.time()

    http = packet.getlayer(HTTPRequest)
    if(len(http.fields) <= howManyValidFields):
        ip = packet.getlayer(IP)
        if ip.src in request_times: 
            last_time = request_times[ip.src]
            if (cur_time - last_time) < timeout_threshold:
                returnString = f"Slowloris attack detected from {ip.src}"
                return True
        request_times[ip.src] = cur_time
   
def incoming_filter(packet):
    return packet.haslayer(HTTPRequest)

def detectMain(iface, return_dict):
    print("Detecting Slowloris attack...")
    s = sniff(lfilter=incoming_filter, iface=iface, stop_filter=detect_slowloris)
    return_dict[0] = returnString
"""
