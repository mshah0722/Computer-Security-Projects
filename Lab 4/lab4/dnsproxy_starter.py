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

def clientSide(data):
    clientUDPSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        serverSend = clientUDPSocket.sendto(data, (host, dns_port))
        datarecv, server = clientUDPSocket.recvfrom(BUFF_SIZE)
    finally:
	clientUDPSocket.close()

def serverSide():
    serverTCPSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    serverTCPSocket.bind((host, port))
    data, address = serverTCPSocket.recvfrom(BUFF_SIZE)
    dataReceivedBack = client(data)
    serverSend = sock.sendto(dataReceivedBack, address)

serverSide()
