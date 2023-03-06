from scapy.all import *
from tools.mongo_con import myDB
import tools.constants as CONSTANTS
import argparse
import math
import time

packet_request_counter = 0
packet_response_counter = 0

def process_data(collection_packets, collection_drop, packet):
    time.sleep(0.1)
    global packet_request_counter
    packet_request_counter += 1
    timestamp = packet.time*1000 #get the time in milli-seconds
    packet_id = packet[IP].id
    packet_src = getIPSrc(packet) #check with intermediate nodes - in IRT, we have 2 intermediate nodes
    packet_dst = getIPDst(packet) #check with intermediate nodes - in IRT, we have 2 intermediate nodes
    if packet_src == CONSTANTS.IP_gNB:
        direction = "uplink"
    elif packet_src == CONSTANTS.IP_UPF:
        direction = "downlink"
    else : direction = None
    data = {"packet_id": packet_id, "src": packet_src, "dst": packet_dst, "timestamp1": timestamp, "direction": direction}
    query_filter = {"packet_id": packet_id}
    result = myDB.findOne(collection_packets, query_filter, {})
    if result : #if the packet already exists, calculate the delay and update by adding the delay to the packet
        global packet_response_counter
        packet_response_counter += 1
        # return the timestamp of the existing object
        query_filter = {"packet_id": packet_id}
        field_to_retreive = {"timestamp1":1}
        prev_timestamp = (myDB.findOne(collection_packets, query_filter, field_to_retreive))["timestamp1"]
        delay = abs(timestamp - prev_timestamp)
        update = {"$set": {"timestamp2": timestamp, "delay": delay}}
        myDB.updateOne(collection_packets, query_filter, update)
    else :
        myDB.insert(collection_packets,data)
    print(packet_request_counter, " packets requests -- ", packet_response_counter, " packets responses", end="\r")
    packet_drop_ratio = (1 - packet_response_counter/packet_request_counter)*100
    drop_data = {"dropped_packets": packet_drop_ratio}
    myDB.insert(collection_drop, drop_data)

def wrapper_function_sniff(collection_packets, collection_drop):
    return lambda packet: process_data(collection_packets, collection_drop, packet)


def gtp_filter(packet):
    allowed_hosts = [CONSTANTS.IP_gNB, CONSTANTS.IP_UPF, CONSTANTS.IP_intermediate_1, CONSTANTS.IP_intermediate_2]
    allowed_upd_ports = [CONSTANTS.PORT_UDP_1, CONSTANTS.PORT_UDP_2]
    if packet.haslayer(UDP) and packet[UDP].dport in allowed_upd_ports and packet[IP].src in allowed_hosts and packet[IP].dst in allowed_hosts:
        return True
    return False

def icmp_filter(packet):
    allowed_hosts = [CONSTANTS.IP_gNB, CONSTANTS.IP_UPF, CONSTANTS.IP_intermediate_1, CONSTANTS.IP_intermediate_2]
    if packet.haslayer(ICMP) and packet[IP].src in allowed_hosts and packet[IP].dst in allowed_hosts:
        return True
    return False

def sniff_packets(iface, filter_function, collection_packets, collection_drop):
    if iface:
        sniff(lfilter=filter_function, prn=wrapper_function_sniff(collection_packets, collection_drop), iface=iface, store=0)
    else:
        sniff(lfilter=filter_function, prn=wrapper_function_sniff(collection_packets, collection_drop), store=0)

def getIPSrc(IPpacket):
    if IPpacket[IP].src in [CONSTANTS.IP_gNB, CONSTANTS.IP_UPF]:
        packet_src = IPpacket[IP].src
    elif IPpacket[IP].src in [CONSTANTS.IP_intermediate_1, CONSTANTS.IP_intermediate_2]:
        if IPpacket[IP].src == CONSTANTS.IP_intermediate_1:# this node is masquerading the IP
            packet_src = CONSTANTS.IP_UPF
        elif IPpacket[IP].src == CONSTANTS.IP_intermediate_2: # this node is masquerading the IP
            packet_src = CONSTANTS.IP_gNB
    else : print("src IP address not recognized")
    return packet_src

def getIPDst(IPpacket):
    if IPpacket[IP].dst in [CONSTANTS.IP_gNB, CONSTANTS.IP_UPF]:
        packet_dst = IPpacket[IP].dst
    elif IPpacket[IP].dst in [CONSTANTS.IP_intermediate_1, CONSTANTS.IP_intermediate_2]:
        if IPpacket[IP].dst == CONSTANTS.IP_intermediate_1: # this node is masquerading the IP
            packet_dst = CONSTANTS.IP_UPF
        elif IPpacket[IP].dst == CONSTANTS.IP_intermediate_2: # this node is masquerading the IP
            packet_dst = CONSTANTS.IP_gNB
    return packet_dst

def main():
    # Initialize parser
    msg = "sniffs GTP packets between n1 and n2, and get packet_id, src, dst and time_sent/rev. Then, send these information to Mongodb Atlas.\
    Note that there might be intermediate nodes e.g., n1, n2, etc. Verify if the intermediate nodes masquerade the IP"
    parser = argparse.ArgumentParser(description = msg)
    #add network interface argument
    parser.add_argument("-i", "--iface", help = "add the network interface", type=str, required=True)
    args = parser.parse_args()
    iface = args.iface #eth1

    myDB.initialize()
    function_map = {"icmp_filter" :icmp_filter, "gtp_filter" :gtp_filter}
    if CONSTANTS.FILTER in function_map:
        filter_function = function_map[CONSTANTS.FILTER]
    sniff_packets(iface, filter_function, CONSTANTS.COLLECTION_NAME_PACKETS, CONSTANTS.COLLECTION_NAME_DROP)

if __name__ == "__main__":
    main()
