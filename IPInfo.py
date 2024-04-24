class IPInfo:
    def __init__(self, src_ip, dst_ip, proto, tos, ttl, flags, id):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.proto = proto
        self.tos = tos
        self.ttl = ttl
        self.flags = flags
        self.id = id