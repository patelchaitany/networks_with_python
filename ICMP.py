#only for educational purposes
#help taken from black-hat python book
import socket
import os
import struct
import threading
from ipaddress import ip_address, ip_network
from ctypes import *

listening_host = "192.168.0.187" # your ip addr

target_subnet = "192.168.0.0/24"

magic_message = "MYSECRETRULES!"
def secret_udp_sender(subnet, magic_msg):
    sender_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    for ip in ip_network(subnet).hosts():
        sender_socket.sendto(magic_msg.encode('utf-8'), (str(ip), 65212))


class MyIP(Structure):
    _fields_ = [
        ("ihl", c_ubyte, 4),
        ("version", c_ubyte, 4),
        ("tos", c_ubyte),
        ("length", c_ushort),
        ("id", c_ushort),
        ("offset", c_ushort),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte),
        ("checksum", c_ushort),
        ("src", c_uint32),
        ("dst", c_uint32)
    ]

    def __new__(cls, socket_buff=None):
        return cls.from_buffer_copy(socket_buff)

    def __init__(self, socket_buff=None):
        self.socket_buff = socket_buff

        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

        self.source_address = socket.inet_ntoa(struct.pack("@I", self.src))
        self.destination_address = socket.inet_ntoa(struct.pack("@I", self.dst))

        try:
            self.protocol_name = self.protocol_map[self.protocol_num]
        except IndexError:
            self.protocol_name = str(self.protocol_num)


class MyICMP(Structure):
    _fields_ = [
        ("type", c_ubyte),
        ("code", c_ubyte),
        ("checksum", c_ushort),
        ("unused", c_ushort),
        ("next_hop_mtu", c_ushort)
    ]

    def __new__(cls, socket_buff):
        return cls.from_buffer_copy(socket_buff)

    def __init__(self, socket_buff):
        self.socket_buff = socket_buff
if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

sniffer_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

sniffer_socket.bind((listening_host, 0))

sniffer_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

if os.name == "nt":
    sniffer_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

sender_thread = threading.Thread(target=secret_udp_sender, args=(target_subnet, magic_message))
sender_thread.start()

try:
    while True:

        packet_buffer = sniffer_socket.recvfrom(65535)[0]

        ip_hdr = MyIP(packet_buffer[:20])

        print("Protocol: %s %s -> %s" % (
            ip_hdr.protocol_name,
            ip_hdr.source_address,
            ip_hdr.destination_address)
              )

        if ip_hdr.protocol_name == "ICMP":

            offset = ip_hdr.ihl * 4
            icmp_buf = packet_buffer[offset:offset + sizeof(MyICMP)]

            icmp_hdr = MyICMP(icmp_buf)

            print("ICMP -> Type: %d Code: %d" % (
                icmp_hdr.type,
                icmp_hdr.code)
                  )

            if icmp_hdr.code == 3 and icmp_hdr.type == 3:

                if ip_address(ip_hdr.source_address) in ip_network(target_subnet):
                    if packet_buffer[len(packet_buffer) - len(magic_message):] == magic_message:
                        print("Host Up: %s" % ip_hdr.source_address)


except KeyboardInterrupt:

    if os.name == "nt":
        sniffer_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
