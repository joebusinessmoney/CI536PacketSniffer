import tkinter as tk
from tkinter import ttk
import scapy.all as scapy

class View(ttk.Frame):
    def __init__(self, parent, os):
        super().__init__(parent)

        self.os = os
        
        # set the controller
        self.controller = None

        self.interface_var = tk.StringVar(value="")

        interfaces = scapy.ifaces

        self.label = ttk.Label(self, text='List of Currently Detected Interfaces - Please Click the Interface You Would Like to Sniff From and Click the "Sniff" Button:')
        self.label.grid(row=1, column=0, pady=10)

        # Handling for Windows, Darwin, and Linux
        self.interface_radios = []
        for index, iface_id in enumerate(interfaces):
            iface = interfaces[iface_id]
            # Get the user-friendly description of the interface, if available
            description = iface.description if hasattr(iface, 'description') else iface.name
            radio = ttk.Radiobutton(self, text=description, variable=self.interface_var, value=iface.name)
            radio.grid(row=index + 2, column=0, pady=10)
            self.interface_radios.append(radio)

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

    def showMessage(self, message, color):
        self.message_label['text'] = message
        self.message_label['foreground'] = color
        self.message_label.after(3000, self.hideMessage)

    def showError(self, message):
        self.showMessage(message, 'red')

    def showSuccess(self, message):
        self.showMessage(message, 'green')
        # Reset the form
        self.interface_var.set("")

    def hideMessage(self):
        self.message_label['text'] = ''