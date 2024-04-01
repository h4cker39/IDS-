from scapy.all import sniff
from scapy.all import IP, ICMP, sr1, ARP, send, TCP
from scapy.all import Raw
import os
import socket 

IPs = ""
def detect_syn_flood(packet):
     if packet.haslayer("TCP") and packet["TCP"].flags == 'S':
            print("SYN packet detected from")

def detect_port_scan(packet):
  if packet.haslayer("TCP") and packet["TCP"].flags == 'S' and packet["TCP"].dport == 22: #(packet["TCP"].dport >= 0 or packet["TCP"].dport <= 9000 ) and (packet["TCP"].dport !=80 and packet["TCP"].dport !=443 and packet["TCP"].dport !=8080) :
            print("Possible port scan detected fri", packet["IP"].src)
            print("Probing the target...")         
            target = str(packet["IP"].src)
            print(target)
            #global IPs
            #IPs = target
            if(target == "" or target == False):
                     print("NO IP DETECTED")
                     return 0
        
            cmd  = "nmap -O " + str((packet["IP"].src))
            print(cmd)
            os.system(cmd)
    
    
def packet_dispatcher(packet):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    my_local_ip = str(s.getsockname()[0])   
    if packet.haslayer("TCP") and packet["TCP"].flags == 'S' and packet["TCP"].dport == 22 and packet["IP"]: 
            ip_src=packet['IP'].src
            #print(ip_src + " ::::: " + my_local_ip)
            if(str(ip_src) == my_local_ip):
                ""
            else:
               cmd = "nmap -O "+ str(ip_src)
               os.system(cmd)
  
    

def start_capture():
    sniff(prn=packet_dispatcher,count=200)


start_capture()
