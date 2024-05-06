class Controller():
    def __init__(self, model, view):
        self.model = model
        self.view = view

    def setInterface(self, interface):
        self.model.setInterface(interface)

    def stopSniffing(self):
        self.model.stopSniffing()

    def startSniffing(self):
        self.model.startSniffing()

    def analyse(self):
        self.model.analyse()
    
    def setFilter(self, filter_string):
        self.model.setFilter(filter_string)
    
    def clearFilter(self):
        self.model.clearFilter()
        self.view.refreshPacketList()

