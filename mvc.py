import tkinter as tk
from tkinter import ttk
from model import Model
from view import View
from controller import Controller

class MVC(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title('Welcome')

        # create a model
        model = Model('hello@gmail.com')

        # create a view and place it on the root window
        view = View(self)
        view.grid(row=0, column=0, padx=10, pady=10)

        # create a controller
        controller = Controller(model, view)

        # set the controller to view
        view.set_controller(controller)