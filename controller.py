class Controller():
    def __init__(self, model, view):
        self.model = model
        self.view = view

    def setInterface(self, interface):
        self.model.setInterface(interface)