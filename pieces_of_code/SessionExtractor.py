

from scapy.all import *
from SessionAnalyzer import *


class SessionExtractor:
	"""Extract sessions"""
	def __init__(self,r):
		self.sessions={}
		self.regexp=[]
		for expression in r : 
			self.regexp.append(re.compile(expression))
		

	def addToSession(self, packet):
		sess = session_extractor(packet)
		if not sess in self.sessions : 
			self.sessions[sess]=SessionAnalyzer()
		html=self.sessions[sess].assemble(packet)
		if not html is None : 
			for r in self.regexp :
				for line in html.split("\n") :
					ma=r.search(line) 
					if not  ma is None : 
						print("=====>"+ sess+"\n"+html+"\n\n\n")


def session_extractor(p):
            sess = "Other"
            if 'Ether' in p:
                if 'IP' in p:
                    if 'TCP' in p:
                        sess = p.sprintf("TCP %IP.src%:%r,TCP.sport% > %IP.dst%:%r,TCP.dport%")
                    elif 'UDP' in p:
                        sess = p.sprintf("UDP %IP.src%:%r,UDP.sport% > %IP.dst%:%r,UDP.dport%")
                    elif 'ICMP' in p:
                        sess = p.sprintf("ICMP %IP.src% > %IP.dst% type=%r,ICMP.type% code=%r,ICMP.code% id=%ICMP.id%")
                    else:
                        sess = p.sprintf("IP %IP.src% > %IP.dst% proto=%IP.proto%")
                elif 'ARP' in p:
                    sess = p.sprintf("ARP %ARP.psrc% > %ARP.pdst%")
                else:
                    sess = p.sprintf("Ethernet type=%04xr,Ether.type%")
            return sess

