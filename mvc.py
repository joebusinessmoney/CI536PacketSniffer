import tkinter as tk
from tkinter import ttk
from model import Model
from view import View
from controller import Controller

class MVC(tk.Tk):
    def __init__(self, os):
        try:
            super().__init__()

            self.title('Packet Sniffer')

            # create a model
            model = Model()

            # create a view and place it on the root window
            view = View(self, os)
            view.grid(row=0, column=0, padx=10, pady=10)

            # create a controller
            controller = Controller(model, view)

            # set the controller to view
            view.setController(controller)

            model.set_view(view)
        except Exception as error:
            print(error)
