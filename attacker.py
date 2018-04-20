"""
Author: Doron Goldman
An python program implenting man in the middle attack through arp spoofing
"""

import scapy.all as sp
import sys
import os
import time

sp.conf.verb = 0
BROADCAST = "ff:ff:ff:ff:ff:ff"

def get_mac(IP):
    """
    args:
    IP:  an ip address
    returns: return the corresponding mac adress
    using the basic arp protocol to discover the targets real mac addres
    """
    print IP
    ans, uans = sp.srp(sp.Ether(dst=BROADCAST) / sp.ARP(pdst=IP),
                       timeout=2, inter=0.1)
    for snd, rcv in ans:
        print rcv
        # Formmated mac address
        return rcv.sprintf(r"%Ether.src%")
        
victimIP, gateIP = tuple(raw_input("pls enter " + x + " ") for x in ["victimIP", "gateIP"])
print get_mac(victimIP)



