import scapy.all as scapy

def packet_sniffer(interface):
    try:
        # Sniff packets on the specified interface
        scapy.sniff(iface=interface, store=False, prn=process_packet)
    except Exception as e:
        print(f"Error: {str(e)}")

def process_packet(packet):
    try:
        # Extract relevant information from the packet
        if packet.haslayer(scapy.IP):
            source_ip = packet[scapy.IP].src
            destination_ip = packet[scapy.IP].dst
            protocol = packet[scapy.IP].proto
            payload = packet[scapy.Raw].load if packet.haslayer(scapy.Raw) else None

            print(f"Source IP: {source_ip}, Destination IP: {destination_ip}, Protocol: {protocol}, Payload: {payload}")
    except Exception as e:
        pass

def main():
    interface = input("Enter the interface to sniff (e.g., 'eth0' or 'wlan0'): ")
    print("Packet Sniffer started. Press Ctrl+C to stop.")
    packet_sniffer(interface)

if __name__ == "__main__":
    main()