
from scapy.all import *
from scapy.layers.inet import *
import time

request_times = {}
returnString = ""

TARGET_PORT = 5000
THRESHOLD = 3
WINDOW = 3

def detect_slowloris(packet):
    global request_times
    global returnString

    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return False

    ip = packet[IP]
    tcp = packet[TCP]

    if tcp.dport != TARGET_PORT:
        return False

    now = time.time()
    src = ip.src

    if src not in request_times:
        request_times[src] = []

    request_times[src].append(now)
    request_times[src] = [t for t in request_times[src] if now - t <= WINDOW]

    print(f"{src} possible Slowloris packets in last {WINDOW}s: {len(request_times[src])}")

    if len(request_times[src]) > THRESHOLD:
        returnString = f"Slowloris attack detected from {src}"
        return True

    return False

def incoming_filter(packet):
    return packet.haslayer(IP) and packet.haslayer(TCP)

def detectMain(iface, return_dict):
    print("Detecting Slowloris attack...")
    sniff(
        lfilter=incoming_filter,
        iface=iface,
        stop_filter=detect_slowloris,
        store=False
    )
    return_dict[0] = returnString



"""
from scapy.all import *
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
