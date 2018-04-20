"""
Author: Doron Goldman
An python program implenting man in the middle attack through arp spoofing
"""

import scapy.all as sp
import sys
import os
import time

sp.conf.verb = 0
BROADCAST = "ff:ff:ff:ff:ff"

victimIP, gateIP = tuple(raw_input("pls enter " + x + " ") for x in ["victimIP", "gateIP"])
print get_mac(victimIP)


def get_mac(IP)
    """
    args:
    IP:  an ip address
    returns: return the corresponding mac adress
    using the basic arp protocol to discover the targets real mac addres
    """
    ans, uans = sp.srp(Ethr(dst=BROADCAST) / ARP(pdst=IP),
                       timeout=2, inter=0.1)
    for snd, rcv in ans:
        print rcv
        # Formmated mac address
        return rcv.sprintf(r"%Ether.src%")
