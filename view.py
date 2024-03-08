import tkinter as tk
import scapy.all as scapy
from tkinter import ttk

class View(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)

        # set the controller
        self.controller = None

        interfaces = (scapy.ifaces)

        self.label = ttk.Label(self, text='List of Currently Detected Interfaces - Please Enter the Name of the Interface You Would Like to Sniffing')
        self.label.grid(row=1, column=0)

        # Iterate over the interfaces and display them
        for index, interface in enumerate(interfaces):
            label_text = f"{index + 1}. {interface}"
            interface_label = ttk.Label(self, text=label_text)
            interface_label.grid(row=index + 2, column=0)

        # email entry
        self.interface_var = tk.StringVar()
        self.interface_entry = ttk.Entry(self, textvariable=self.interface_var, width=5)
        self.interface_entry.grid(row=len(interfaces) + 2, column=0, sticky=tk.NSEW)

        # save button
        self.save_button = ttk.Button(self, text='Sniff', command=self.sniff_button_clicked)
        self.save_button.grid(row=len(interfaces) + 3, column=0, padx=10)

        # message
        self.message_label = ttk.Label(self, text='', foreground='red')
        self.message_label.grid(row=len(interfaces) + 4, column=0)

    def set_controller(self, controller):
        self.controller = controller

    def sniff_button_clicked(self):
        if self.controller:
            self.controller.setInterface(self.interface_var.get())

    def show_error(self, message):
        self.message_label['text'] = message
        self.message_label['foreground'] = 'red'
        self.message_label.after(3000, self.hide_message)
        self.interface_entry['foreground'] = 'red'

    def show_success(self, message):
        self.message_label['text'] = message
        self.message_label['foreground'] = 'green'
        self.message_label.after(3000, self.hide_message)

        # reset the form
        self.interface_entry['foreground'] = 'black'
        self.interface_var.set('')

    def hide_message(self):
        self.message_label['text'] = ''