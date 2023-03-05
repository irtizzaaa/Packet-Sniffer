import scapy.all as scapy

# define a callback function to handle each packet
def packet_callback(packet):
    # extract the source and destination IP addresses from the packet
    src_ip = packet[scapy.IP].src
    dst_ip = packet[scapy.IP].dst
    
    # if the packet has a TCP layer, extract the source and destination port numbers
    if packet.haslayer(scapy.TCP):
        src_port = packet[scapy.TCP].sport
        dst_port = packet[scapy.TCP].dport
        print(f"TCP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
    
    # if the packet has a UDP layer, extract the source and destination port numbers
    elif packet.haslayer(scapy.UDP):
        src_port = packet[scapy.UDP].sport
        dst_port = packet[scapy.UDP].dport
        print(f"UDP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

# start sniffing packets on the network
scapy.sniff(filter="ip", prn=packet_callback)
