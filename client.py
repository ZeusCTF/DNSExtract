#Information is being gleaned from the below notable sources:
#https://unit42.paloaltonetworks.com/dns-tunneling-how-dns-can-be-abused-by-malicious-actors/, https://techwithrohit.medium.com/dns-exfiltration-what-and-how-of-it-dc2dd70f0337

from scapy.all import *

ans = sr1(IP(dst="8.8.8.8")/UDP(sport=RandShort(), dport=53)/DNS(rd=1,qd=DNSQR(qname="secdev.org",qtype="A")))
