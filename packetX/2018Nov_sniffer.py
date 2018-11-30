import os
import sys
import socket
import struct
from ctypes import *

#This is the IP Class inherited from Structure.
class IP(Structure):

    #A fields attribute is required to be able to parse the buffer into 1, 2 or
    #4 byte sections as below
    _fields_ = [
        ("ihl", c_ubyte, 4),
        ("version", c_ubyte, 4),
        ("tos", c_ubyte),
        ("len", c_ushort),
        ("id", c_ushort),
        ("offset", c_ushort),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum", c_ushort),
        ("src", c_uint32),
        ("dst", c_uint32)
    ]

    #Class in created by pass the buffer. _fields_ will parse it into class
    #attributes
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    #class is then instantiated with further attributes
    def __init__(self, socket_buffer=None):
        #create a mapping between IP protocol numbers and names
        self.protocol_map = {
            1: "ICMP",
            6: "TCP",
            17: "UDP"
        }

        #assign the protocol attribute
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)

        #We need human-readable addresses so the the decimal values are "packed"
        #into python bytes with struct and use the socket method below to represent it.
        #Formal definition: Convert a 32-bit packed IPv4 address (a bytes-like object
        #four bytes in length) to its standard dotted-quad string representation
        # (for example, ‘123.45.67.89’).
        
        self.ip_src = socket.inet_ntoa(struct.pack("<L", self.src))
        self.ip_dst = socket.inet_ntoa(struct.pack("<L", self.dst))

#create sniffer socket and bind. We will collect IP headers
sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
try:
    sniffer.bind(("0.0.0.0", 0))
except:
    sys.exit(1)

#Receive the 20 bytes of the IP Header, parse and print the output with the help
#of the IP class above
try:
    while True:
        #Enable promiscuous mode for Windows OS
        if os.name == "nt":
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        buffer = sniffer.recvfrom(65565)[0]
        ip_buffer = buffer[0:20]
        ip_header = IP(ip_buffer)
        print(f"{ip_header.protocol}    {ip_header.ip_src} --> {ip_header.ip_dst}")

except KeyboardInterrupt:
    #Disable promiscuous mode for Windows OS
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    sys.exit(0)
