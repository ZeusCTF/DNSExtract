import socket

def main():
   
   #creating a UDP socket, and binding all addresses to listen on 53
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(("0.0.0.0", 53))  

    while True:
        data, client_address = server_socket.recvfrom(1024) #gathers client request info
        
        # Construct DNS response with NXDOMAIN
        response = construct_nxdomain_response(data)
        
        info = parse_dns_query(data)

        # Send NXDOMAIN response back to the client
        server_socket.sendto(response, client_address)
    
def parse_dns_query(data):
    # Extract the domain name from the DNS query
    domain = b""
    i = 12  # DNS header is 12 bytes
    while data[i] != 0:
        domain += data[i:i+1]
        i += 1
    return domain

def construct_nxdomain_response(data):
    # Extract the transaction ID from the query
    transaction_id = data[:2]

    # Construct DNS response with NXDOMAIN flag
    response = transaction_id + b"\x81\x83" + b"\x00\x01\x00\x00\x00\x00\x00\x00" + data[12:]

    return response

if __name__ == "__main__":
    main()
