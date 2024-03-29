import tkinter as tk
from tkinter import ttk
import scapy.all as scapy

class View(ttk.Frame):
    def __init__(self, parent, os):
        super().__init__(parent)

        self.os = os
        
        # set the controller
        self.controller = None

        interfaces = scapy.ifaces

        self.label = ttk.Label(self, text='List of Currently Detected Interfaces - Please Enter the Name of the Interface You Would Like to Sniff')
        self.label.grid(row=1, column=0, pady=10)

        # Handling for Windows
        if os == 'Windows':
            # Get the list of network interfaces
            for index, iface_id in enumerate(interfaces):
                iface = interfaces[iface_id]
                # Get the user-friendly description of the interface, if available
                description = iface.description if hasattr(iface, 'description') else iface.name
                label_text = f"{index + 1}. {description}"
                interface_label = ttk.Label(self, text=label_text)
                interface_label.grid(row=index + 2, column=0, pady=5)
        elif os in ['Darwin', 'Linux']:
            # Handling for Darwin and Linux
            for index, iface_id in enumerate(interfaces):
                iface = interfaces[iface_id]
                label_text = f"{index + 1}. {iface.name}"
                interface_label = ttk.Label(self, text=label_text)
                interface_label.grid(row=index + 2, column=0, pady=5)
        else:
            self.showError("The Detected Operating System is not Supported by this Packet Sniffer")

         # Interface entry
        self.interface_var = tk.StringVar()
        self.interface_entry = ttk.Entry(self, textvariable=self.interface_var, width=15)
        self.interface_entry.grid(row=2 + len(interfaces), column=0, pady=10)

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
            self.controller.setInterface(self.interface_var.get())

    def showMessage(self, message, color):
        self.message_label['text'] = message
        self.message_label['foreground'] = color
        self.message_label.after(3000, self.hideMessage)

    def showError(self, message):
        self.showMessage(message, 'red')
        self.interface_entry['foreground'] = 'red'

    def showSuccess(self, message):
        self.showMessage(message, 'green')

        # Reset the form
        self.interface_entry['foreground'] = 'black'
        self.interface_var.set('')

    def hideMessage(self):
        self.message_label['text'] = ''