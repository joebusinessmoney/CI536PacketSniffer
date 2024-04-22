from view import View
import scapy.all as scapy

class Model():
    def __init__(self):
        self.chosenInterface = None
        self.view = None
        self.interfaces = scapy.ifaces 

    def set_view(self, view):
        self.view = view

    def sniff(self, chosenInterface): 
        scapy.sniff(iface=chosenInterface, store=False, prn=self.processPacket) 

    def processPacket(self, packet):
        packet.show()

    def setInterface(self, interface):
        self.chosenInterface = interface
         
        self.interfaceSelected()

    def interfaceSelected(self):
        self.view.showSuccess("Interface Selected, Beginning sniffing ...")