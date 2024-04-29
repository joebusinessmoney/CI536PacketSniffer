class Packet:
    def __init__(self):
        self.ether = None
        self.ip = None
        self.tcp = None
        self.udp = None
        self.icmp = None
        self.raw = None