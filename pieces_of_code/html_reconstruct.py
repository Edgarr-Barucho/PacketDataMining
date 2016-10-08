import re
import zlib
from scapy.all import *



picture_directory="./pics"
face_directory="./face"
pcap_file="./autoSniff.pcap"

nSession=1

def get_http_header(http_payload):
	try:
		# print("\n\n=======PAYLOAD=======\n\n"+str(http_payload))
		headers_raw = http_payload[:http_payload.index(b"\r\n\r\n")+2]
		# print("\n\n=======HEADER RAW=======\n\n"+str(headers_raw))
		headers = dict(re.findall(b"\n(?P<name>.*?): (?P<value>.*?)\r",headers_raw))
		# print("\n\n=======HEADER=======\n\n"+str(headers))
	except : 
		return None

	# print(headers)

	if not b"Content-Type" in headers : 
		return None
	return headers


def extract_image(headers, content):
	image=None
	image_type=None

	# print(str(headers)+"\n\n")

	# try :
	if b"image" in headers[b"Content-Type"] :
		# print("image "+headers['Content-Type'])
		image_type = headers[b"Content-Type"].split(b"/")[1]
		image=content

		print("\n\n"+str(image_type)+"\n\n"+str(image))

		print(type(image))
	if b"Content-Encoding" in headers.keys() :
		print("trying to decompress...")
		try :
			if headers[b"Content-Encoding"] == b"gzip":
				image = zlib.decompress(content, 16+zlib.MAX_WBITS)
			elif headers[b"Content-Encoding"] == b"deflate":
				image = zlib.decompress(content)
		except :
			print("failed decompression")
			pass
	# except : 
	# 	print("fail to get image")
	# 	return None, None
	if not content == None : 
		print("sucksex!!")
	return image, image_type



def http_assembler(pcap_file):


	a=rdpcap(pcap_file)
	sessions = a.sessions()

	k=0
	for session in sessions : 

		print("*****************************NEW SESSION*******************************")

		if k == 1 : break
		http_payload = b""
		content=b""
		headers = None
		
		for packet in sessions[session] : 


			try :
				packet.show()
			# 	if packet[TCP].dport == 80 or packet[TCP].sport == 80 :
			# 		http_payload=bytes(packet[TCP].payload)
			# 		print("=======================================================================")
			# 		print( "packet Tcp raw :\n"+ str(http_payload))
			# 		h = get_http_header(bytes(http_payload))
			# 		print("\n\nheader : \n"+str(h))
			# 		if headers is None : headers = h
			# 		if h is None :
			# 			content += http_payload
			# 		else : 
			# 			content += http_payload[http_payload.index(b"\r\n\r\n")+4:]
			# 		print("\n\ncontent : \n"+str(content,encoding="utf-8"))
			# 		# print(type(packet[TCP].payload))
			# 		# print(bytes(packet[TCP].payload))
			# 		# http_payload+=str(packet[TCP].payload)#, encoding="utf-8")
			# 		#, encoding="utf-8")
			# 		# print(http_payload) 
			# except :
			# 	pass

		# print(http_payload)
		# headers = get_http_header(http_payload)

	# 	if headers is None :
	# 		continue
	# 	image, image_type = extract_image(headers, content)
	# 	if image is not None and image_type is not None : 
	# 		file_name = pcap_file+"-pic_carver_"+str(carved_images)+"."+str(image_type)
	# 		fd = open(picture_directory+"/"+file_name,"wb")
	# 		# print(image)
	# 		fd.write(image)
	# 		fd.close()
	# 		carved_images+=1
	# 		k+=1
	# return carved_images
 





def http_session_assembler(session):
	http_payload = ""
	for packet in session : 

		try :
			if packet[TCP].dport == 80 or packet[TCP].sport == 80 :
				http_payload+=str(packet[TCP].payload)
		except :
			pass
	return http_payload


# carved_images= 
http_assembler(pcap_file)
# print("extracted "+str(carved_images)+" images")