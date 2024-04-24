class Packet:
    def __init__(self):
        self.ether = None
        self.ip = None
        self.tcp = None
        self.udp = None
        self.icmp = None
        self.raw = None
    
    def get_ether_src_mac(self):
        if self.ether:
            return self.ether.src_mac
        return None

    def get_ether_dst_mac(self):
        if self.ether:
            return self.ether.dst_mac
        return None

    def get_ether_type(self):
        if self.ether:
            return self.ether.ether_type
        return None

    def get_ip_src_ip(self):
        if self.ip:
            return self.ip.src_ip
        return None

    def get_ip_dst_ip(self):
        if self.ip:
            return self.ip.dst_ip
        return None

    def get_ip_proto(self):
        if self.ip:
            return self.ip.proto
        return None

    def get_ip_tos(self):
        if self.ip:
            return self.ip.tos
        return None

    def get_ip_ttl(self):
        if self.ip:
            return self.ip.ttl
        return None

    def get_ip_flags(self):
        if self.ip:
            return self.ip.flags
        return None

    def get_ip_id(self):
        if self.ip:
            return self.ip.id
        return None

    def get_tcp_src_port(self):
        if self.tcp:
            return self.tcp.src_port
        return None

    def get_tcp_dst_port(self):
        if self.tcp:
            return self.tcp.dst_port
        return None

    def get_tcp_seq(self):
        if self.tcp:
            return self.tcp.seq
        return None

    def get_tcp_ack(self):
        if self.tcp:
            return self.tcp.ack
        return None

    def get_tcp_flags(self):
        if self.tcp:
            return self.tcp.flags
        return None

    def get_tcp_window(self):
        if self.tcp:
            return self.tcp.window
        return None

    def get_udp_src_port(self):
        if self.udp:
            return self.udp.src_port
        return None

    def get_udp_dst_port(self):
        if self.udp:
            return self.udp.dst_port
        return None

    def get_udp_len(self):
        if self.udp:
            return self.udp.len
        return None

    def get_udp_checksum(self):
        if self.udp:
            return self.udp.checksum
        return None

    def get_icmp_type(self):
        if self.icmp:
            return self.icmp.type
        return None

    def get_icmp_code(self):
        if self.icmp:
            return self.icmp.code
        return None

    def get_icmp_id(self):
        if self.icmp:
            return self.icmp.id
        return None

    def get_icmp_seq(self):
        if self.icmp:
            return self.icmp.seq
        return None

    def get_raw_load(self):
        if self.raw:
            return self.raw.load
        return None