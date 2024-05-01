import customtkinter as ctk
from model import Model
from view import View
from controller import Controller

class MVC(ctk.CTk):
    def __init__(self, os):
        try:
            super().__init__()

            self.title('Packet Sniffer')


            # Ensuring the window is brought to front after initialization
            self.after(100, self.bring_to_front)

            # Create a model
            model = Model()

            # Create a view and place it on the root window
            view = View(self, os)
            view.grid(row=0, column=0, padx=10, pady=10)

            # Create a controller
            controller = Controller(model, view)

            # Set the controller to view
            view.setController(controller)

            # Link the model back to the view for updates
            model.set_view(view)
        except Exception as error:
            print(f"Initialization Error: {error}")

    def create_widgets(self):
        # widget
        label = ctk.CTkLabel(self, text="Initialize UI Components Here")
        label.pack(pady=20)

    def bring_to_front(self):
        """Bring the window to the front and set focus."""
        self.attributes('-topmost', True)  # Make the window always on top
        self.after(500, lambda: self.attributes('-topmost', False))  # Turn off always on top after 500 ms
        self.focus_force()


