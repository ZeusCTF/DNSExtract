import socket

def dns_response(query):
    pass
    #I believe the best response would be an NXDOMAIN, 

def parse_dns_query(data):
    
    domain = b""
    i = 12 
    while data[i] != 0:
        domain += data[i:i+1]
        i += 1
    return domain

def main():
   
   #creating a UDP socket, and binding all addresses to listen on 53
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(("0.0.0.0", 53))  

    while True:
       

        data, client_address = server_socket.recvfrom(1024) #gathers client request info
        domain = parse_dns_query(data[12:]) #sends data to helper func to parse
        response = dns_response(domain) #creates reply

        
        if response:
            server_socket.sendto(data[:2] + b"\x81\x80" + data[4:6] + data[4:6] + b"\x00\x00\x00\x00" + data[12:] + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + response, client_address)
"""
DNS headers are 12 bytes long, the first data[:2] extracts the first 2 bytes received from the client (which represent the transaction ID)
"""





if __name__ == "__main__":
    main()
