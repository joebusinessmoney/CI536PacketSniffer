import customtkinter as ctk

class CustomList(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.items = []
        self.selected_index = None
        self.on_select_callback = None  # Store the external callback here

        self.canvas = ctk.CTkCanvas(self, width=400, height=300)
        self.canvas.pack(side='left', fill='both', expand=True)

        self.scrollbar = ctk.CTkScrollbar(self, command=self.canvas.yview)
        self.scrollbar.pack(side='right', fill='y')
        self.canvas.config(yscrollcommand=self.scrollbar.set)

        self.scrollable_frame = ctk.CTkFrame(self.canvas)
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor='nw')
        self.scrollable_frame.bind('<Configure>', self._on_frame_configure)

        self.font = ("Helvetica", 14)

    def _on_frame_configure(self, event=None):
        self.canvas.configure(scrollregion=self.canvas.bbox('all'))

    def insert(self, index, text):
        def _select(idx, event=None):
            self.select(idx)
            
            if self.on_select_callback:
                self.on_select_callback(event)
                item = ctk.CTkButton(self.scrollable_frame, text=text, fg_color='gray', hover_color='gray30',
                         font=self.font, height=40, command=lambda idx=len(self.items): _select(idx))
                item.pack(fill='x', padx=10, pady=5, expand=True)
                self.items.append(item)


    def select(self, index):
        if self.selected_index is not None:
            self.items[self.selected_index].configure(fg_color='gray')  # Deselect previous item
        self.selected_index = index
        self.items[index].configure(fg_color='blue')  # Highlight the selected item

    def curselection(self):
        """Return the currently selected index as a tuple, or an empty tuple if nothing is selected."""
        return (self.selected_index,) if self.selected_index is not None else ()

    def register_select_callback(self, callback):
        """Registers a callback function that will be called on item selection."""
        self.on_select_callback = callback

    def yview_moveto(self, fraction):
        """Scroll the canvas view to a specific fraction of the scroll region."""
        self.canvas.yview_moveto(fraction)
