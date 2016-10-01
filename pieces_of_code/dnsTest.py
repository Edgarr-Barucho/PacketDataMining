import dns.resolver
 
host = "www.cuisineaz.com"
 
answers_IPv4 = dns.resolver.query(host, 'A')
for rdata in answers_IPv4:
    print("IPv4 : "+str(rdata.address))
 
answers_IPv6 = dns.resolver.query(host, 'AAAA')
for rdata in answers_IPv6:
    print( "IPv6 : "+str(rdata.address))