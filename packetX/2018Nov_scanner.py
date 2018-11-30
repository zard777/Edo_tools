# Credit: @ismailakkila

import socket
import struct
import threading
import sys
import os
import time
from ctypes import *
from netaddr import IPNetwork, IPAddress

class ICMP(Structure):
    _fields_ = [
        ("type", c_ubyte),
        ("code", c_ubyte),
        ("checksum", c_ushort),
        ("unused", c_ushort),
        ("next_hop_mtu", c_ushort),
        ("ip_header", c_uint32)
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        pass

class IP(Structure):
    _fields_ = [
        ("ihl", c_ubyte, 4),
        ("version", c_ubyte, 4),
        ("tos", c_ubyte),
        ("length", c_ushort),
        ("identification", c_ushort),
        ("offset", c_ushort),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte),
        ("checksum", c_ushort),
        ("src", c_uint32),
        ("dst", c_uint32),
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.protocol_map = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
        }

        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)

        self.ip_src = socket.inet_ntoa(struct.pack("<L", self.src))
        self.ip_dst = socket.inet_ntoa(struct.pack("<L", self.dst))

def udp_sender(subnet, packet_data):
    time.sleep(5)
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for ip in IPNetwork(subnet):
        try:
            udp_socket.sendto(packet_data, (str(ip), 1337))
        except:
            pass

subnet = "10.0.0.0/16"
packet_data = b"DEMODEMO"

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
try:
    sniffer.bind(("0.0.0.0", 0))
except:
    sys.exit(1)
print(f"[*] Sniffer Bind Success")

try:
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    t = threading.Thread(target=udp_sender, args=(subnet, packet_data))
    t.start()

    while True:
        raw_buffer = sniffer.recvfrom(65565)[0]
        #print(raw_buffer)

        ip_header_buffer = raw_buffer[0:20]
        ip_header = IP(ip_header_buffer)

        offset = ip_header.ihl * 4
        icmp_buffer = raw_buffer[offset: offset + sizeof(ICMP)]
        icmp = ICMP(icmp_buffer)

        if (ip_header.ip_src != "127.0.0.1" or ip_header.ip_dst != "127.0.0.1"):
            #print(f"{ip_header.protocol}    {ip_header.ip_src}  =>  {ip_header.ip_dst}")
            if ip_header.protocol == "ICMP" and icmp.type == 3 and icmp.code == 3:
                if IPAddress(ip_header.ip_src) in IPNetwork(subnet):
                    if raw_buffer[len(raw_buffer) - len(packet_data):] == packet_data:
                        print(f"Host Up: {ip_header.ip_src}")
except KeyboardInterrupt:
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    sys.exit(0)
