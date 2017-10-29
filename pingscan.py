#! /usr/bin/env python3

import socket
import argparse
import ipaddress
import random
import struct
import time
import select

ICMP_ECHO_REQUEST = 8
ICMP_CODE = socket.getprotobyname("icmp")

def ones_comp_add16_list(list):
    s = 0
    for byte in list:
        c = 0
        s = byte + s
        c += s >> 16
        s = (s & 0xffff) + c

    return s

def checksum(data):
    """Generates checksum for ICMP packet"""
    # reference: https://tools.ietf.org/html/rfc1071

    #if len(data) % 4:
    #    data += (0).to_bytes(2, byteorder="big", signed=False)

    d = []
    for i in range(0, len(data), 2):
        n = (data[i:i+2])
        d.append((n[1] << 8) + n[0]) # Swap bytes

    s = ones_comp_add16_list(d).to_bytes(2, byteorder="big", signed=False)
    # Swap bytes back
    sum = (s[1] << 8) + s[0]
    sum = sum
    # Not sure why this needs to be XOR'd
    return (sum ^ 0xffff)


def receive_ping(sock, packet_id, time_sent, timeout):
    while True:
        ready = select.select([sock], [], [], timeout)
        if ready[0] == []:
            print("empty")
            return
        packet, addr = sock.recvfrom(1024)
        icmp_header = packet[20:28]
        type, code, checksum, p_id, sequence = struct.unpack(
                'bbHHh', icmp_header)
        if p_id == packet_id:
            return time.time()

def create_packet(id):
    """Create new ICMP echo packet with the given ID"""
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, 0, id, socket.htons(1))

    print("header: {0}".format(list(header)))
    data = ('A'*8).encode()
    cksum = checksum(header + data)
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, socket.htons(cksum), id, socket.htons(1))

    return header + data

def icmp_scan(host):
    """ICMP scan a given network"""
    dest_addr = host.exploded

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)

    packet_id = int(random.random() * 65534) # correct?
    packet = create_packet(packet_id)
    time_sent = time.time()

    while packet:
        print("packet: {0}".format(list(packet)))
        sent = sock.sendto(packet, (dest_addr, 1))
        packet = packet[sent:]

    time_recv = receive_ping(sock, packet_id, time.time(), 5)

    print("Delay: {0}".format(time_recv - time_sent))
    
    return

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan IP addresses with ICMP")
    parser.add_argument('--network', type=ipaddress.ip_network, help="Network to scan")
    parser.add_argument('--host', type=ipaddress.ip_address, help="Network to scan")

    args = parser.parse_args()

    icmp_scan(args.host)
