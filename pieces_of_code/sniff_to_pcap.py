from scapy.all import *

def packet_callback(packet):
	print(packet)


interface="eth0"
bpf_filter="host 192.168.0.10"
packets=sniff(count=1000, filter=bpf_filter, iface=interface, prn=packet_callback)
wrpcap('autoSniff.pcap',packets)



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


def test(pl):
	content = b""
	header = None
	n=0
	for packet in pl :
		print("packet : #"+str(n))
		n+=1
		# packet.show()
		if TCP in packet and Raw in packet:
			print("\n\n===========content : =============\n"+str(content)+"\n\n")
			http_payload = packet[TCP].load
			h=None
			h = get_http_header(http_payload)
			if not h is None :
				if not header is None and b"Content-Type" in header :
					text=content
					if header[b"Content-Encoding"] == b"gzip":
						print("trying to decompress : \n\n"+str(content[content.index(b'\x1f\x8b'):]))
						text = zlib.decompress(content[content.index(b'\x1f\x8b'):], 16+zlib.MAX_WBITS)
					elif header[b"Content-Encoding"] == b"deflate":
						text = zlib.decompress(content)
					print(str(text,encoding="utf-8"))
				header = h
				content=http_payload[http_payload.index(b"\r\n\r\n")+4:]
				print("reset content to : "+str(content))
				text=""
			else :
				print("adding "+str(http_payload) +"to content")
				content += http_payload
