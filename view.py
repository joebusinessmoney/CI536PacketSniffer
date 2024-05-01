import tkinter as tk
from tkinter import ttk
import scapy.all as scapy
import customtkinter as ctk
from Packet import Packet

class View(ttk.Frame):
    def __init__(self, parent, os):
        super().__init__(parent)
        self.os = os
        self.controller = None
        self.packets_listbox = None
        self.interface_var = tk.StringVar(value="")
        self.interfaces = scapy.ifaces

        self.setupUI()

    def setupUI(self):
        # Labels
        ctk.CTkLabel(self, text='List of Currently Detected Interfaces').grid(row=0, column=0, columnspan=2, pady=(10, 5), sticky='w')
        ctk.CTkLabel(self, text='Please select an interface to sniff from:').grid(row=1, column=0, columnspan=2, pady=(5, 10), sticky='w')

        # Interface Radiobuttons
        for index, iface_id in enumerate(self.interfaces):
            iface = self.interfaces[iface_id]
            description = iface.description if hasattr(iface, 'description') else iface.name
            ctk.CTkRadioButton(self, text=description, variable=self.interface_var, value=iface.name).grid(row=index + 2, column=0, columnspan=2, sticky='w')

        # Sniff button
        self.sniff_button = ctk.CTkButton(self, text='Sniff', command=self.sniffButtonClicked)
        self.sniff_button.grid(row=len(self.interfaces) + 2, column=0, columnspan=2, pady=10)

        # Message label
        self.message_label = ctk.CTkLabel(self, text='')
        self.message_label.grid(row=len(self.interfaces) + 3, column=0, columnspan=2, pady=5)
        

    def setController(self, controller):
        self.controller = controller

    def sniffButtonClicked(self):
        selected_interface = self.interface_var.get()
        if selected_interface:
            self.controller.setInterface(selected_interface)
            self.controller.startSniffing()
            self.displayFilterBar()  # Display filter bar after starting sniffing
        else:
            self.showError("Please select an interface.")

    def showError(self, message):
        self.message_label['text'] = message
        self.after(3000, self.hideMessage)

    def hideMessage(self):
        self.message_label['text'] = ''

    def updateUI(self):
        self.removeInterface()
        self.createPacketListBox()

    def removeInterface(self):
        for widget in self.winfo_children():
            widget.grid_remove()

    def createPacketListBox(self):
        self.packets_listbox = tk.Listbox(self, width=100, font=('Arial', 18), borderwidth=0, highlightthickness=0)
        self.packets_listbox.grid(row=0, column=0, columnspan=2, pady=(10, 5), padx=10, sticky='w')
        self.packets_listbox.bind('<<ListboxSelect>>', self.showPacketInfo)

        self.sniffing_button = ttk.Button(self, text='Stop', command=self.stopSniffing)
        self.sniffing_button.grid(row = 1, column=0, columnspan=2)

        self.remove_filter_button = tk.Button(self, text="Remove Filter", command=self.removeFilter)
        self.remove_filter_button.grid(row=len(self.interfaces) + 5, column=1, padx=(10, 5), pady=5, sticky="w")


        


    def stopSniffing(self):
        self.controller.stopSniffing()
    
    def startSniffing(self):
        self.controller.startSniffing()

    def updateButton(self, action):
        if action == "Start":
            self.sniffing_button.configure(text="Start", command=self.startSniffing)
        else:
            self.sniffing_button.configure(text="Stop", command=self.stopSniffing)

    def updatePackets(self, packet):
        packet_info = self.formatPacketInfo(packet)
        self.packets_listbox.insert(tk.END, packet_info)
        self.packets_listbox.yview_moveto(1.0)

    def formatPacketInfo(self, packet):
        if packet.ip:
            src_ip = packet.ip.src_ip
            dst_ip = packet.ip.dst_ip
            protocol_ip = packet.ip.proto
            protocol = "Unknown"

            if protocol_ip == 6:
                protocol = "TCP"
            elif protocol_ip == 17:
                protocol = "UDP"
            elif protocol_ip == 1:
                protocol = "ICMP"

            return f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}"
        elif packet.ether:
            src_mac = packet.ether.src_mac
            dst_mac = packet.ether.dst_mac
            ether_type = packet.ether.ether_type
            protocol = "Unknown"

            if ether_type == 2048:
                protocol = "IPv4"
            elif ether_type == 2054:
                protocol = "ARP"
                if dst_mac == "ff:ff:ff:ff:ff:ff":
                    dst_mac = "BROADCAST"
            elif ether_type == 34525:
                protocol = "IPv6"

            return f"Source MAC: {src_mac}, Destination MAC: {dst_mac}, Protocol: {protocol}"
        else:
            return "No Information Available"
        

    def showPacketInfo(self, event):
        selected_index = self.packets_listbox.curselection()
        if selected_index:
            packet_window = tk.Toplevel(self)
            packet_window.title("Packet Information")

            packet_info = self.controller.model.packets[selected_index[0]]

            try:

                if packet_info.ether:
                    src_mac = packet_info.ether.src_mac
                    dst_mac = packet_info.ether.dst_mac
                    type_mac = packet_info.ether.ether_type

                    packet_ether = tk.Label(packet_window, text="Ethernet:")
                    packet_ether_src = tk.Label(packet_window, text="Source MAC:" + str(src_mac))
                    packet_ether_dst = tk.Label(packet_window, text="Destination MAC:" + str(dst_mac))
                    packet_ether_type = tk.Label(packet_window, text="Ether Type:" + str(type_mac))

                    packet_ether.pack()
                    packet_ether_src.pack()
                    packet_ether_dst.pack()
                    packet_ether_type.pack()
            
                if packet_info.ip:
                    src_ip = packet_info.ip.src_ip
                    dst_ip = packet_info.ip.dst_ip
                    proto_ip = packet_info.ip.proto
                    tos_ip = packet_info.ip.tos
                    ttl_ip = packet_info.ip.ttl
                    flags_ip = packet_info.ip.flags
                    id_ip = packet_info.ip.id

                    packet_ip = tk.Label(packet_window, text="IP:")
                    packet_ip_src = tk.Label(packet_window, text="Source IP:" + str(src_ip))
                    packet_ip_dst = tk.Label(packet_window, text="Destination IP:" + str(dst_ip))
                    packet_ip_proto = tk.Label(packet_window, text="Protocol:" + str(proto_ip))
                    packet_ip_tos = tk.Label(packet_window, text="Type of Service:" + str(tos_ip))
                    packet_ip_ttl = tk.Label(packet_window, text="Time to Live:" + str(ttl_ip))
                    packet_ip_flags = tk.Label(packet_window, text="Set Flags:" + str(flags_ip))
                    packet_ip_id = tk.Label(packet_window, text="ID:" + str(id_ip))

                    packet_ip.pack()
                    packet_ip_src.pack()
                    packet_ip_dst.pack()
                    packet_ip_proto.pack()
                    packet_ip_tos.pack()
                    packet_ip_ttl.pack()
                    packet_ip_flags.pack()
                    packet_ip_id.pack()
            
                if packet_info.tcp:
                    src_tcp = packet_info.tcp.src_port
                    dst_tcp = packet_info.tcp.dst_port
                    seq_tcp = packet_info.tcp.seq
                    ack_tcp = packet_info.tcp.ack
                    flags_tcp = packet_info.tcp.flags
                    window_tcp = packet_info.tcp.window

                    packet_tcp = tk.Label(packet_window, text="TCP:")
                    packet_tcp_src = tk.Label(packet_window, text="Source Port:" + str(src_tcp))
                    packet_tcp_dst = tk.Label(packet_window, text="Destination Port:" + str(dst_tcp))
                    packet_tcp_seq = tk.Label(packet_window, text="Sequence:" + str(seq_tcp))
                    packet_tcp_ack = tk.Label(packet_window, text="Acknowledge:" + str(ack_tcp))
                    packet_tcp_flags = tk.Label(packet_window, text="Flags:" + str(flags_tcp))
                    packet_tcp_window = tk.Label(packet_window, text="Window:" + str(window_tcp))

                    packet_tcp.pack()
                    packet_tcp_src.pack()
                    packet_tcp_dst.pack()
                    packet_tcp_seq.pack()
                    packet_tcp_ack.pack()
                    packet_tcp_flags.pack()
                    packet_tcp_window.pack()

                if packet_info.udp:
                    src_udp = packet_info.udp.src_port
                    dst_udp = packet_info.udp.dst_port
                    len_udp = packet_info.udp.len
                    checksum_udp = packet_info.udp.checksum

                    packet_udp = tk.Label(packet_window, text="UDP:")
                    packet_udp_src = tk.Label(packet_window, text="Source Port:" + str(src_udp))
                    packet_udp_dst = tk.Label(packet_window, text="Destination Port:" + str(dst_udp))
                    packet_udp_len = tk.Label(packet_window, text="Length:" + str(len_udp))
                    packet_udp_checksum = tk.Label(packet_window, text="Checksum:" + str(checksum_udp))

                    packet_udp.pack()
                    packet_udp_src.pack()
                    packet_udp_dst.pack()
                    packet_udp_len.pack()
                    packet_udp_checksum.pack()

                if packet_info.icmp:
                    type_icmp = packet_info.icmp.type
                    code_icmp = packet_info.icmp.code
                    id_icmp = packet_info.icmp.id
                    seq_icmp = packet_info.icmp.seq

                    packet_icmp = tk.Label(packet_window, text="ICMP:")
                    packet_icmp_type = tk.Label(packet_window, text="Type:" + str(type_icmp))
                    packet_icmp_code = tk.Label(packet_window, text="Code:" + str(code_icmp))
                    packet_icmp_id = tk.Label(packet_window, text="ID:" + str(id_icmp))
                    packet_icmp_seq = tk.Label(packet_window, text="Sequence:" + str(seq_icmp))

                    packet_icmp.pack()
                    packet_icmp_type.pack()
                    packet_icmp_code.pack()
                    packet_icmp_id.pack()
                    packet_icmp_seq.pack()

                if packet_info.raw:
                    raw_data = packet_info.raw.load

                    packet_raw = tk.Label(packet_window, text="Raw:")
                    packet_raw.pack()

                    
                    chunk_size = 16
                    for i in range(0, len(raw_data), chunk_size):
                        chunk = raw_data[i:i + chunk_size]
                        chunk_hex = ' '.join(f"{byte:02x}" for byte in chunk)
                        tk.Label(packet_window, text=chunk_hex).pack()

            except:
                packet_none = tk.Label(packet_window, text="Information not Available")
                packet_none.pack()

    def removeFilter(self):
        # Clear the filter entry widget
        self.filter_entry.delete(0, tk.END)

        # Resets any filter conditions in the model and refresh the packet list
        if self.controller:
            self.controller.clearFilter()
            self.refreshPacketList()  # refreshes the packet display
        
    def refreshPacketList(self):
        # Clear and re-display all packets or as per the current model state
        self.packets_listbox.delete(0, tk.END)
        for packet in self.controller.model.packets:
            self.updatePackets(packet)

    def displayFilterBar(self):
        # Check if filter elements already exist to prevent recreation
            if not hasattr(self, 'filter_entry'):
                self.filter_entry = tk.Entry(self)
                self.filter_entry.grid(row=len(self.interfaces) + 4, column=0, padx=(10, 5), pady=(5, 5), sticky="ew")
                self.filter_button = tk.Button(self, text="Apply Filter", command=self.applyFilter)
                self.filter_button.grid(row=len(self.interfaces) + 4, column=1, padx=(10, 5), pady=5, sticky="w")

    def applyFilter(self):
        filter_string = self.filter_entry.get().strip()
        self.filterPackets(filter_string)

    def filterPackets(self, filter_string):
        self.packets_listbox.delete(0, tk.END)  # Clear the listbox before applying the new filter
        filter_string = filter_string.lower()  # Convert filter string to lowercase once

    # Filter and display packets
        for packet in self.controller.model.packets:
        # Determine the protocol from the packet attributes
            if packet.tcp:
                protocol = "TCP"
            elif packet.udp:
                protocol = "UDP"
            elif packet.icmp:
                protocol = "ICMP"
            else:
                protocol = "Unknown"

        # Check if the filter string is in the source IP or the protocol
            if hasattr(packet, 'ip') and packet.ip and (filter_string in packet.ip.src_ip.lower() or filter_string in protocol.lower()):
                self.updatePackets(packet)
