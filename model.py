from view import View
from Packet import Packet
from EtherInfo import EtherInfo
from IPInfo import IPInfo
from ICMPInfo import ICMPInfo
from RawInfo import RawInfo
from TCPInfo import TCPInfo
from UDPInfo import UDPInfo
import time
import scapy.all as scapy
import threading
from ai import AI


class Model():
    def __init__(self):
        self.chosenInterface = None
        self.view = None
        self.interfaces = scapy.ifaces 
        self.packets = []     
        self.sniff_event = threading.Event()
        self.sniff_event.set() 
        self.filter = ""


    def set_view(self, view):
        self.view = view

    def sniff(self, chosenInterface): 
        threading.Thread(target=self.sniff_thread, args=(chosenInterface,), daemon=True).start()

    def sniff_thread(self, chosenInterface):
        while self.sniff_event.is_set():
            if self.filter:
                packets = scapy.sniff(iface=chosenInterface, filter=self.filter, prn=self.processPacket, timeout=1)
            else:
                packets = scapy.sniff(iface=chosenInterface, prn=self.processPacket, timeout=1)

    def processPacket(self, packet):
        packet_info = Packet()

        if packet.haslayer(scapy.Ether):
            ether_info = EtherInfo(
                src_mac=packet[scapy.Ether].src,
                dst_mac=packet[scapy.Ether].dst,
                ether_type=packet[scapy.Ether].type
            )
            packet_info.ether = ether_info

        if packet.haslayer(scapy.IP):
            ip_info = IPInfo(
                src_ip=packet[scapy.IP].src,
                dst_ip=packet[scapy.IP].dst,
                proto=packet[scapy.IP].proto,
                tos=packet[scapy.IP].tos,
                ttl=packet[scapy.IP].ttl,
                flags=packet[scapy.IP].flags,
                id=packet[scapy.IP].id
            )
            packet_info.ip = ip_info

        if packet.haslayer(scapy.TCP):
            tcp_info = TCPInfo(
                src_port=packet[scapy.TCP].sport,
                dst_port=packet[scapy.TCP].dport,
                seq=packet[scapy.TCP].seq,
                ack=packet[scapy.TCP].ack,
                flags=packet[scapy.TCP].flags,
                window=packet[scapy.TCP].window
            )
            packet_info.tcp = tcp_info

        if packet.haslayer(scapy.UDP):
            udp_info = UDPInfo(
                src_port=packet[scapy.UDP].sport,
                dst_port=packet[scapy.UDP].dport,
                len=packet[scapy.UDP].len,
                checksum=packet[scapy.UDP].chksum
            )
            packet_info.udp = udp_info

        if packet.haslayer(scapy.ICMP):
            icmp_info = ICMPInfo(
                type=packet[scapy.ICMP].type,
                code=packet[scapy.ICMP].code,
                id=packet[scapy.ICMP].id,
                seq=packet[scapy.ICMP].seq
            )
            packet_info.icmp = icmp_info

        if packet.haslayer(scapy.Raw):
            raw_info = RawInfo(
                load=packet[scapy.Raw].load
            )
            packet_info.raw = raw_info

        self.packets.append(packet_info)
        self.view.updatePackets(packet_info)

    def setInterface(self, interface):
        self.chosenInterface = interface
        self.interfaceSelected()
        self.sniff(self.chosenInterface)

    def interfaceSelected(self):
        self.view.updateUI()

    def stopSniffing(self):
        self.sniff_event.clear()
        self.view.updateButton("Start")

    def startSniffing(self):
        self.sniff_event.set()
        threading.Thread(target=self.sniff_thread, args=(self.chosenInterface,), daemon=True).start()
        self.view.updateButton("Stop")

    def analyse(self):
        ai = AI(self)
        self.sniff_event.clear()
        self.view.updateButton("Pause")
        ai.startProcessing()
    
    def endAnalyse(self):
        self.sniff_event.set()
        threading.Thread(target=self.sniff_thread, args=(self.chosenInterface,), daemon=True).start()
        self.view.updateButton("Unpause")

    def getPackets(self):
        return self.packets

    def restartSniffing(self):
        # Restart sniffing with the new filter
        self.stopSniffing()
        self.startSniffing()
    
    def setFilter(self, filter_string):
        self.filter = filter_string
        if self.sniff_event.is_set():  # Check if sniffing is active
            self.restartSniffing()
    
    def clearFilter(self):
        self.filter = ""

    

