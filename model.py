import scapy.all as scapy
import os
from view import View

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
        result = False

        for available_interface in self.interfaces:
            if self.chosenInterface == available_interface:
                result = True

        if (result == True):
            self.interfaceSuccess()
        else:
            self.interfaceError()

    def interfaceSuccess(self):
        self.view.show_success("Valid interface selected, starting sniffing.")

    def interfaceError(self):
        self.view.show_error("No matching interface. Please choose from the ones listed above")