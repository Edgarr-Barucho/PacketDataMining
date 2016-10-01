import re
import zlib
from scapy.all import *



picture_directory="a"
face_directory="b"
pcap_file="c"



def get_http_header(http_payload):
	try:
		headers_raw = http_payload[:http_payload.index("\\r\\n\\r\\n")+2]
		headers = dict(re.findall(r"(?P<'name>.*?): (?P<value>.*?)\r\n",headers_raw))
	except : 
		return None

	if not "Content-Type" in header : 
		return None
	return headers

def http_assembler(pcap_file):

	carved_images = 0
	faces_detected = 0

	a=rdpcap(pcap_file)
	sessions = a.sessions()

	for session in sessions : 
		http_payload = ""
		
		for packet in sessions[session] : 

			try :
				if packet[TCP].dport == 80 or packet[TCP].sport == 80 :
					http_payload+=str(packet[TCP].payload)
			except :
				pass

		headers = get_http_headers(http_payload)

		if headers is None :
			continue
		image, image_type = extract_image(headers, http_payload)
		if image is not None and image_type is not None : 
			file_name = pcap_file+"-pic_carver_"+carved_images+"."+image_type
			fd = open(picture_directory+"/"+file_name,"wb")
			fd.write(image)
			fd.close()
			carved_images+=1





def http_session_assembler(session):
	http_payload = ""
	for packet in session : 

		try :
			if packet[TCP].dport == 80 or packet[TCP].sport == 80 :
				http_payload+=str(packet[TCP].payload)
		except :
			pass
	return http_payload