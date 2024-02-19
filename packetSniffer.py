import socket
import sys
import scapy.all as scapy
import platform

def startUp():
    print("*** Welcome to the Packet Sniffer ***")
    print("")

    print("*** Operating System Detected: " + platform.system() + " ***")
    print("")

    print(scapy.ifaces)

    print("")
    print("*** List of Currently Detected Interfaces - Please Enter the Name of the Interface You Would Like to Sniffing ***")
    print("*** NOTE - If No Selection made, Sniffing will Happen on all Interfaces ***")
    userInput = input("")


    sniff(userInput) # network interface to be sniffed (should add ability for user to select an interface of their choice)

def sniff(interface):
    scapy.sniff(store=False, prn=processPacket) # packet sniffer function, takes network interface as
                                                                 # an input, captured packets wont be stalled, processPacket
                                                                 # will be called each time a new packet is captured

def processPacket(packet): # this gets the packets, source and destination ip and port as well as the protocol and displays accordingly
    if packet.haslayer(scapy.IP):              
        sourceIP = packet[scapy.IP].src
        destinationIP = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        print("Source: " + str(sourceIP) + " Destination: " + str(destinationIP) + " Protocol: " + str(protocol))

    if packet.haslayer(scapy.TCP):
        sourcePort = packet[scapy.TCP].sport
        destinationPort = packet[scapy.TCP].dport
        print("TCP Packet: Source: " + str(sourceIP) + " Port: " + str(sourcePort) + " --> Destination " + str(destinationIP) + " Port: " + str(destinationPort)) 

    if packet.haslayer(scapy.UDP):
        sourcePort = packet[scapy.UDP].sport
        destinationPort = packet[scapy.UDP].dport
        print("UDP Packet: Source: " + str(sourceIP) + " Port: " + str(sourcePort) + " --> Destination " + str(destinationIP) + " Port: " + str(destinationPort))

    if packet.haslayer(scapy.ICMP):
        print("ICMP Packet: " + str(sourceIP) + " --> " + str(destinationIP))

startUp()