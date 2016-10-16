from scapy.all import *
from SessionExtractor import *


extractor = SessionExtractor(["activity"])
interface="eth0"

def callback(p):
	extractor.addToSession(p)

packets=sniff(count=10000000000, iface=interface, prn=callback)