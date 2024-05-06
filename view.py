import tkinter as tk
from tkinter import ttk
import scapy.all as scapy
import customtkinter as ctk
from Packet import Packet

class View(ctk.CTkFrame):
    def __init__(self, parent, os):
        super().__init__(parent)
        self.os = os
        self.controller = None
        self.packets_listbox = None
        self.interface_var = tk.StringVar(value="")
        self.interfaces = scapy.ifaces

        self.setupUI()
    
    #styling elements

    def green_button_style(widget):
        widget.configure(fg_color="#20C20E", hover_color="#16880A")

    def red_button_style(widget):
        widget.configure(fg_color="#FF4122", hover_color="#ED3419")        

    def application_style(master):
        master.configure(fg_color="#404040", border_color="#404040")

    def blue_button_style(widget):
        widget.configure(fg_color="#24A0ED", hover_color="#006DB5")


    def setupUI(self):

        View.application_style(self)        

        # Labels
        self.title = ctk.CTkLabel(self, text='List of Currently Detected Interfaces', text_color="white").grid(row=0, column=0, columnspan=2, pady=(10, 5), sticky='w', padx=(5))
        self.subtitle = ctk.CTkLabel(self, text='Please select an interface to sniff from:', text_color="white").grid(row=1, column=0, columnspan=2, pady=(5, 10), sticky='w', padx=(10))

        # Interface Radiobuttons
        for index, iface_id in enumerate(self.interfaces):
            iface = self.interfaces[iface_id]
            description = iface.description if hasattr(iface, 'description') else iface.name
            ctk.CTkRadioButton(self, text=description, variable=self.interface_var, value=iface.name, fg_color="#20C20E", hover_color="#16880A", text_color="white", border_color="white").grid(row=index + 2, column=0, columnspan=2, sticky='w', padx=(10), pady=(5))
        

        # Sniff button
        self.sniff_button = ctk.CTkButton(self, text='Sniff', command=self.sniffButtonClicked)
        View.green_button_style(self.sniff_button)
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
        self.packets_listbox = tk.Listbox(self, width=100, font=('sans_serif', 18), borderwidth=0, highlightthickness=0, bg="#404040", fg="white", selectbackground="#16880A", selectforeground="white")
        self.packets_listbox.grid(row=0, column=0, columnspan=2, pady=(10, 5), padx=10, sticky='w')
        self.packets_listbox.bind('<<ListboxSelect>>', self.showPacketInfo)

        self.sniffing_button = ctk.CTkButton(self, text='Stop', command=self.stopSniffing)
        View.red_button_style(self.sniffing_button)
        self.sniffing_button.grid(row=len(self.interfaces) + 3, column=1, padx=(10, 5), pady=5, sticky="w")

        self.remove_filter_button = ctk.CTkButton(self, text="Remove Filter", command=self.removeFilter)
        View.red_button_style(self.remove_filter_button)
        self.remove_filter_button.grid(row=len(self.interfaces) + 4, column=1, padx=20, pady=5)

        self.analyse_button = ctk.CTkButton(self, text='Analyse', command=self.analyse)
        View.blue_button_style(self.analyse_button)
        self.analyse_button.grid(row=len(self.interfaces) + 3, column=1, padx=20, pady=5)

    def stopSniffing(self):
        self.controller.stopSniffing()
    
    def startSniffing(self):
        self.controller.startSniffing()

    def analyse(self):
        self.controller.analyse()

    def updateButton(self, action):
        if action == "Pause":
            self.sniffing_button.configure(state=tk.DISABLED)
            self.analyse_button.configure(state=tk.DISABLED)
            self.filter_button.configure(state=tk.DISABLED)
            self.remove_filter_button.configure(state=tk.DISABLED)
        elif action == "Unpause":
            self.sniffing_button.configure(state=tk.NORMAL)
            self.analyse_button.configure(state=tk.NORMAL)
            self.filter_button.configure(state=tk.NORMAL)
            self.remove_filter_button.configure(state=tk.NORMAL)
        elif action == "Start":
            self.sniffing_button.configure(text="Start", command=self.startSniffing)
            View.green_button_style(self.sniffing_button)
        elif action == "Stop":
            self.sniffing_button.configure(text="Stop", command=self.stopSniffing)
            View.red_button_style(self.sniffing_button)

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
        

    def removeFilter(self):
            self.filter_entry.delete(0, tk.END)

            if self.controller:
                self.controller.clearFilter()
                self.refreshPacketList()  # refreshes the packet display
            
    def refreshPacketList(self):
            self.packets_listbox.delete(0, tk.END)
            for packet in self.controller.model.packets:
                self.updatePackets(packet)

    def displayFilterBar(self):
                if not hasattr(self, 'filter_entry'):
                    self.filter_entry = ctk.CTkEntry(self, placeholder_text="Enter IP or Protocol to filter")
                    self.filter_entry.grid(row=len(self.interfaces) + 4, column=0, padx=(10, 5), pady=(5, 5), sticky="ew")
                    self.filter_button = ctk.CTkButton(self, text="Apply Filter", command=self.applyFilter)
                    View.blue_button_style(self.filter_button)
                    self.filter_button.grid(row=len(self.interfaces) + 4, column=1, padx=(10, 5), pady=5, sticky="w")

    def applyFilter(self):
            filter_string = self.filter_entry.get().strip()
            self.filterPackets(filter_string)

    def filterPackets(self, filter_string):
            self.packets_listbox.delete(0, tk.END)  # Clear the listbox before applying the new filter
            filter_string = filter_string.lower()  # Convert filter string to lowercase once

            for packet in self.controller.model.packets:
                if packet.tcp:
                    protocol = "TCP"
                elif packet.udp:
                    protocol = "UDP"
                elif packet.icmp:
                    protocol = "ICMP"
                else:
                    protocol = "Unknown"

                if hasattr(packet, 'ip') and packet.ip and (filter_string in packet.ip.src_ip.lower() or filter_string in protocol.lower()):
                    self.updatePackets(packet)


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
            packet_window = tk.Toplevel(self, background="#404040")
            packet_window.title("Packet Information")
            packet_window.geometry("450x600") 

            # Create a frame to contain the packet information
            frame = tk.Frame(packet_window, background="#404040")
            frame.pack(fill=tk.BOTH, expand=True)

            # Create a canvas to enable scrolling
            canvas = tk.Canvas(frame, background="#404040")
            canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

            # Add a scrollbar to the canvas
            scrollbar = tk.Scrollbar(frame, orient=tk.VERTICAL, command=canvas.yview, background="#404040")
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            canvas.config(yscrollcommand=scrollbar.set)

            # Create another frame to hold the actual packet information labels
            inner_frame = tk.Frame(canvas, background="#404040")  
            canvas.create_window((0, 0), window=inner_frame, anchor=tk.NW)
            packet_info = self.controller.model.packets[selected_index[0]]

            # Styling elements for packet info labels
            label_style = {'background': '#404040', 'foreground': 'white', 'anchor': 'w', 'font': ('Helvetica', 16)}
            title_style = {'background': '#404040', 'foreground': 'white', 'font': 'bold, 20', 'relief': 'raised'}
            raw_style = {'background': '#404040', 'foreground': 'white', 'font': ('sans-serif', 12)}

            try:
                if packet_info.ether:
                    src_mac = packet_info.ether.src_mac
                    dst_mac = packet_info.ether.dst_mac
                    type_mac = packet_info.ether.ether_type

                    packet_ether = tk.Label(inner_frame, text="Ethernet:", **title_style)
                    packet_ether_src = tk.Label(inner_frame, text="Source MAC: " + str(src_mac), **label_style)
                    packet_ether_dst = tk.Label(inner_frame, text="Destination MAC: " + str(dst_mac), **label_style)
                    packet_ether_type = tk.Label(inner_frame, text="Ether Type: " + str(type_mac), **label_style)

                    packet_ether.pack()
                    packet_ether_src.pack(fill='x')
                    packet_ether_dst.pack(fill='x')
                    packet_ether_type.pack(fill='x')
            
                if packet_info.ip:
                    src_ip = packet_info.ip.src_ip
                    dst_ip = packet_info.ip.dst_ip
                    proto_ip = packet_info.ip.proto
                    tos_ip = packet_info.ip.tos
                    ttl_ip = packet_info.ip.ttl
                    flags_ip = packet_info.ip.flags
                    id_ip = packet_info.ip.id

                    packet_ip = tk.Label(inner_frame, text="IP:", **title_style)
                    packet_ip_src = tk.Label(inner_frame, text="Source IP: " + str(src_ip), **label_style)
                    packet_ip_dst = tk.Label(inner_frame, text="Destination IP: " + str(dst_ip), **label_style)
                    packet_ip_proto = tk.Label(inner_frame, text="Protocol: " + str(proto_ip), **label_style)
                    packet_ip_tos = tk.Label(inner_frame, text="Type of Service: " + str(tos_ip), **label_style)
                    packet_ip_ttl = tk.Label(inner_frame, text="Time to Live: " + str(ttl_ip), **label_style)
                    packet_ip_flags = tk.Label(inner_frame, text="Set Flags: " + str(flags_ip), **label_style)
                    packet_ip_id = tk.Label(inner_frame, text="ID: " + str(id_ip), **label_style)

                    packet_ip.pack()
                    packet_ip_src.pack(fill='x')
                    packet_ip_dst.pack(fill='x')
                    packet_ip_proto.pack(fill='x')
                    packet_ip_tos.pack(fill='x')
                    packet_ip_ttl.pack(fill='x')
                    packet_ip_flags.pack(fill='x')
                    packet_ip_id.pack(fill='x')
            
                if packet_info.tcp:
                    src_tcp = packet_info.tcp.src_port
                    dst_tcp = packet_info.tcp.dst_port
                    seq_tcp = packet_info.tcp.seq
                    ack_tcp = packet_info.tcp.ack
                    flags_tcp = packet_info.tcp.flags
                    window_tcp = packet_info.tcp.window

                    packet_tcp = tk.Label(inner_frame, text="TCP:", **title_style)
                    packet_tcp_src = tk.Label(inner_frame, text="Source Port: " + str(src_tcp), **label_style)
                    packet_tcp_dst = tk.Label(inner_frame, text="Destination Port: " + str(dst_tcp), **label_style)
                    packet_tcp_seq = tk.Label(inner_frame, text="Sequence: " + str(seq_tcp), **label_style)
                    packet_tcp_ack = tk.Label(inner_frame, text="Acknowledge: " + str(ack_tcp), **label_style)
                    packet_tcp_flags = tk.Label(inner_frame, text="Flags: " + str(flags_tcp), **label_style)
                    packet_tcp_window = tk.Label(inner_frame, text="Window: " + str(window_tcp), **label_style)

                    packet_tcp.pack()
                    packet_tcp_src.pack(fill='x')
                    packet_tcp_dst.pack(fill='x')
                    packet_tcp_seq.pack(fill='x')
                    packet_tcp_ack.pack(fill='x')
                    packet_tcp_flags.pack(fill='x')
                    packet_tcp_window.pack(fill='x')

                if packet_info.udp:
                    src_udp = packet_info.udp.src_port
                    dst_udp = packet_info.udp.dst_port
                    len_udp = packet_info.udp.len
                    checksum_udp = packet_info.udp.checksum

                    packet_udp = tk.Label(inner_frame, text="UDP: ", **title_style)
                    packet_udp_src = tk.Label(inner_frame, text="Source Port: " + str(src_udp), **label_style)
                    packet_udp_dst = tk.Label(inner_frame, text="Destination Port: " + str(dst_udp), **label_style)
                    packet_udp_len = tk.Label(inner_frame, text="Length: " + str(len_udp), **label_style)
                    packet_udp_checksum = tk.Label(inner_frame, text="Checksum: " + str(checksum_udp), **label_style)

                    packet_udp.pack()
                    packet_udp_src.pack(fill='x')
                    packet_udp_dst.pack(fill='x')
                    packet_udp_len.pack(fill='x')
                    packet_udp_checksum.pack(fill='x')

                if packet_info.icmp:
                    type_icmp = packet_info.icmp.type
                    code_icmp = packet_info.icmp.code
                    id_icmp = packet_info.icmp.id
                    seq_icmp = packet_info.icmp.seq

                    packet_icmp = tk.Label(inner_frame, text="ICMP: ", **title_style)
                    packet_icmp_type = tk.Label(inner_frame, text="Type: " + str(type_icmp), **label_style)
                    packet_icmp_code = tk.Label(inner_frame, text="Code: " + str(code_icmp), **label_style)
                    packet_icmp_id = tk.Label(inner_frame, text="ID: " + str(id_icmp), **label_style)
                    packet_icmp_seq = tk.Label(inner_frame, text="Sequence: " + str(seq_icmp), **label_style)

                    packet_icmp.pack()
                    packet_icmp_type.pack(fill='x')
                    packet_icmp_code.pack(fill='x')
                    packet_icmp_id.pack(fill='x')
                    packet_icmp_seq.pack(fill='x')

                if packet_info.raw:
                    raw_data = packet_info.raw.load

                    packet_raw = tk.Label(inner_frame, text="Raw:", **title_style)
                    packet_raw.pack()

                    
                    chunk_size = 19
                    for i in range(0, len(raw_data), chunk_size):
                        chunk = raw_data[i:i + chunk_size]
                        chunk_hex = ' '.join(f"{byte:02x}" for byte in chunk)
                        tk.Label(inner_frame, text=chunk_hex, **raw_style).pack()

            except Exception as e:
                packet_none = tk.Label(inner_frame, text="Information not Available", **label_style)
                packet_none.pack()

        # Bind the canvas to the mouse scroll event
        canvas.bind_all("<MouseWheel>", lambda event: canvas.yview_scroll(int(-1*(event.delta/120)), "units"))

        # Configure canvas to update scroll region
        inner_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

