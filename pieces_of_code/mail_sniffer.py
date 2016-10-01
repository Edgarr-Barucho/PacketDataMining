from scapy.all import *

def packet_callback(packet):
	if IP in packet :
		if "89.248.211.102" == str(packet[IP].dst) :
			print("server : "+packet[IP].dst)
			print(packet.show())
			if packet[TCP].payload : 
				mail_packet = str(packet[TCP].payload)
				print(mail_packet)
	# 	if "user" in mail_packet.lower() or "pass" in mail_packet.lower() :
	# 		print("server : "+packet[IP].dst)
	# 		print(packet[TCP].payload) 

sniff(prn=packet_callback,store=0)


# 216.58.208.205		