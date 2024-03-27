
from scapy.all import sniff
from scapy.all import IP, ICMP, sr1, ARP
import nmap

def detect_syn_flood(packet):
     if packet.haslayer("TCP") and packet["TCP"].flags == 'S':
            print("SYN packet detected from")
         
def detect_port_scan(packet):
  
  if packet.haslayer("TCP") and packet["TCP"].flags == 'S' and (packet["TCP"].dport >= 0 or packet["TCP"].dport <= 9000 ) and (packet["TCP"].dport !=80 and packet["TCP"].dport !=443 and packet["TCP"].dport !=8080) :
            print("Possible port scan detected fri", packet["IP"].src)
            print("Probing the target...")
            nm = nmap.PortScanner()         
            target = str(packet["IP"].src)
            nm.scan(target, arguments="-O")
            print(nm['scan'][target]['osmatch'][0]['osclass'][0]['osfamily'])
            #Here we can use nmap to sniff the operating system but scapy can do it to but not so much accuretly 
            #however will leave it commented if you have nmap and would like to use 
            '''
            if (ip.ttl <= 64):
                 print(" Possibly Linux/Unix")
            elif (ip.ttl <=128):
                 print("Windows")
            elif (macOS_signature):   
                    print("MacOs")
            else:
                    print("No Ip layer")
            #print(f"Host {response.psrc} had MAC Address {response.hwsrc}")
            '''
def packet_dispatcher(packet):
    detect_port_scan(packet)

def start_capture():
    sniff(prn=packet_dispatcher, count=1000)


start_capture()


