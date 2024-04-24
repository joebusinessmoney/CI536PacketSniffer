class UDPInfo:
    def __init__(self, src_port, dst_port, len, checksum):
        self.src_port = src_port
        self.dst_port = dst_port
        self.len = len
        self.checksum = checksum