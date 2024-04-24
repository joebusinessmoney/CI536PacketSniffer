import tkinter as tk
from tkinter import ttk
import scapy.all as scapy
import time
from Packet import Packet

class View(ttk.Frame):
    def __init__(self, parent, os):
        super().__init__(parent)

        self.os = os
        
        # set the controller
        self.controller = None

        self.packets_listbox = None

        self.interface_var = tk.StringVar(value="")

        interfaces = scapy.ifaces

        self.label1 = ttk.Label(self, text='List of Currently Detected Interfaces')
        self.label1.grid(row=1, column=0, pady=10)

        self.label2 = ttk.Label(self, text='Please Click the Interface You Would Like to Sniff From and Click the "Sniff" Button:')
        self.label2.grid(row=2, column=0, pady=10)

        # Handling for Windows, Darwin, and Linux
        self.interface_radios = []
        for index, iface_id in enumerate(interfaces):
            iface = interfaces[iface_id]
            # Get the user-friendly description of the interface, if available
            description = iface.description if hasattr(iface, 'description') else iface.name
            self.radio = ttk.Radiobutton(self, text=description, variable=self.interface_var, value=iface.name)
            self.radio.grid(row=index + 3, column=0, pady=10)
            self.interface_radios.append(self.radio)

        # Sniff button
        self.sniff_button = ttk.Button(self, text='Sniff', command=self.sniffButtonClicked)
        self.sniff_button.grid(row=3 + len(interfaces), column=0, pady=10)

        # Message label
        self.message_label = ttk.Label(self, text='', foreground='black')
        self.message_label.grid(row=4 + len(interfaces), column=0, pady=10)

    def setController(self, controller):
        self.controller = controller

    def sniffButtonClicked(self):
        if self.controller:
            selected_interface = self.interface_var.get()
            if selected_interface:
                self.controller.setInterface(selected_interface)
            else:
                self.showError("Please select an interface.")
        
    def showError(self, message):
        self.message_label['text'] = message
        self.message_label['foreground'] = "red"
        self.interface_var.set("")
        self.message_label.after(3000, self.hideMessage)

    def hideMessage(self):
        self.message_label['text'] = ''

    def updateUI(self):
        time.sleep(3)

        self.removeInterface()

        self.packets_listbox = tk.Listbox(self, width=100)
        self.packets_listbox.grid(row=1, column=0, pady=10, padx=10)

        self.packets_listbox.bind('<<ListboxSelect>>', self.showPacketInfo)

    def removeInterface(self):
        self.label1.grid_remove()
        self.label2.grid_remove()
        for radio in self.interface_radios:
            radio.grid_remove()
        self.sniff_button.grid_remove()
        self.message_label.grid_remove()

    def updatePackets(self, packet): 
        packet_info = self.formatPacketInfo(packet)
        self.packets_listbox.insert(tk.END, packet_info)

        self.packets_listbox.yview_moveto(1.0)

    def formatPacketInfo(self, packet):
        if packet.ether:
            src_mac = packet.ether.src_mac
            dst_mac = packet.ether.dst_mac
            ether_type = packet.ether.ether_type
            return f"Source MAC: {src_mac}, Destination MAC: {dst_mac}, Protocol: {ether_type}"
        else:
            return "No Information Available"

    def showPacketInfo(self, event):
        selected_index = self.packets_listbox.curselection()
        if selected_index:
            packet_info = self.controller.model.packets[selected_index[0]]
            src = packet_info.ether.src_mac if packet_info.ether else "N/A"
            packet_window = tk.Toplevel(self)
            packet_window.title("Packet Information")
            packet_label1 = tk.Label(packet_window, text=src)
            packet_label1.pack()