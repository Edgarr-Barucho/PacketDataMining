from scapy.all import *


class SessionAnalyzer:

	def __init__(self):
		self.currentContent=b""
		self.lastHeader=None


	

	def assemble(self, packet):
		result=None
		
		try :
			# packet.show()
			if TCP in packet and Raw in packet:
				# print("\n\n===========content : =============\n"+str(currentContent)+"\n\n")
				http_payload = packet[TCP].load
				currentHeader = get_http_header(http_payload)
				if not currentHeader is None :
					if not self.lastHeader is None and b"Content-Type" in self.lastHeader :
						text=self.currentContent
						if b"Content-Encoding" in self.lastHeader :
							if self.lastHeader[b"Content-Encoding"] == b"gzip":
								# print("trying to decompress : \n\n"+str(currentContent[currentContent.index(b'\x1f\x8b'):]))
								text = zlib.decompress(self.currentContent[self.currentContent.index(b'\x1f\x8b'):], 16+zlib.MAX_WBITS)
							elif self.lastHeader[b"Content-Encoding"] == b"deflate":
								text = zlib.decompress(self.currentContent)
						result= str(text,encoding="utf-8")
					self.lastHeader = currentHeader
					self.currentContent=http_payload[http_payload.index(b"\r\n\r\n")+4:]
					# print("reset content to : "+str(content))
					text=""
				else :
					# print("adding "+str(http_payload) +"to content")
					self.currentContent += http_payload
		except : 
			pass
		return result

def get_http_header(http_payload):
		try:
			# print("\n\n=======PAYLOAD=======\n\n"+str(http_payload))
			headers_raw = http_payload[:http_payload.index(b"\r\n\r\n")+2]
			# print("\n\n=======HEADER RAW=======\n\n"+str(headers_raw))
			headers = dict(re.findall(b"\n(?P<name>.*?): (?P<value>.*?)\r",headers_raw))
			# print("\n\n=======HEADER=======\n\n"+str(headers))
		except : 
			return None
		if (not b"Content-Type" in headers) and (not b"User-Agent" in headers) : #is there a better way to check this is really a header and not a \r\n\r\n in the tcp load  ? 
			return None
		return headers