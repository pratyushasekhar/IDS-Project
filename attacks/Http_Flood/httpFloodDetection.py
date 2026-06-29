#from scapy.all import *
#from scapy.layers.http import HTTPRequest
#from scapy.layers.inet import *
#import time

#ip_and_number_of_requests = {}
#request_times = {}

#returnString = ""

#def detect_HTTP_Flood(packet):
 #   print(".")

  #  global ip_and_number_of_requests
   # global request_times
    #global returnString

    #=======Changeable Params=======
    #howManyrequestsAreAllowedInAnInterval = 100
    #timeout_threshold = 3
    #===============================

    #cur_time = time.time()

    #ip = packet.getlayer(IP)
    #if ip.src in ip_and_number_of_requests: 
     #   ip_and_number_of_requests[ip.src] += 1
      #  last_time = request_times[ip.src]
       # print(ip.src, ip_and_number_of_requests[ip.src], cur_time-last_time)        
      #  if (cur_time - last_time) < timeout_threshold:
       #     if ip_and_number_of_requests[ip.src] > howManyrequestsAreAllowedInAnInterval:
        #        returnString = f"HTTP Flood attack detected from {ip.src}"
         #       return True
   # else:
    #    ip_and_number_of_requests[ip.src] = 1
    #request_times[ip.src] = cur_time
    
        
#def incoming_filter(packet):
#    return packet.haslayer(HTTPRequest)
 #   return packet.haslayer(TCP)

#def detectMain(iface, return_dict):
 #   print("Detecting Http Flood attack...")
  #  sniff(lfilter=incoming_filter, iface=iface, stop_filter=detect_HTTP_Flood)
   # return_dict[0] = returnString

from scapy.all import *
from scapy.layers.inet import *
import time

request_times = {}
returnString = ""

TARGET_PORT = 5000
THRESHOLD = 100
WINDOW = 3

def detect_HTTP_Flood(packet):
    global request_times
    global returnString

    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return False

    ip = packet[IP]
    tcp = packet[TCP]

    # Count only incoming client requests to Flask server
    if tcp.dport != TARGET_PORT:
        return False

    now = time.time()
    src = ip.src

    if src not in request_times:
        request_times[src] = []

    request_times[src].append(now)

    # Keep only requests in last WINDOW seconds
    request_times[src] = [t for t in request_times[src] if now - t <= WINDOW]

    print(f"{src} requests in last {WINDOW}s: {len(request_times[src])}")

    if len(request_times[src]) > THRESHOLD:
        returnString = f"HTTP Flood attack detected from {src}"
        return True

    return False

def incoming_filter(packet):
    return packet.haslayer(IP) and packet.haslayer(TCP)

def detectMain(iface, return_dict):
    print("Detecting Http Flood attack...")
    sniff(
        lfilter=incoming_filter,
        iface=iface,
        stop_filter=detect_HTTP_Flood,
        store=False
    )
    return_dict[0] = returnString
