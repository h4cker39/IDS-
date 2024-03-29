
from scapy.all import sniff
from scapy.all import IP, ICMP, sr1, ARP, send, TCP
from scapy.all import Raw
def detect_syn_flood(packet):
     if packet.haslayer("TCP") and packet["TCP"].flags == 'S':
            print("SYN packet detected from")

def detect_port_scan(packet):
  if packet.haslayer("TCP") and packet["TCP"].flags == 'S' and (packet["TCP"].dport >= 0 or packet["TCP"].dport <= 9000 ) and (packet["TCP"].dport !=80 and packet["TCP"].dport !=443 and packet["TCP"].dport !=8080) :
            print("Possible port scan detected fri", packet["IP"].src)
            print("Probing the target...")         
            target = str(packet["IP"].src)
            print(target)
            ip = IP(dst=target)

            my_ack=1
            payload = "payloadlobdata"
            payload = Raw(load=payload)
            data_packet = TCP(sport=1500, dport=80, flags="", seq=102, ack=my_ack)
            rs = send(ip/data_packet/payload)
            if(rs):
                 rs.summary()
            else:
                 print("No response received")

            
    
def packet_dispatcher(packet):
    detect_port_scan(packet)

def start_capture():
    sniff(prn=packet_dispatcher, count=500)


start_capture()


