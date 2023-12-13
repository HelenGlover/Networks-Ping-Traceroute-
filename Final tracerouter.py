# Attribution: this assignment is based on ICMP Traceroute Lab from Computer Networking: a Top-Down Approach by Jim Kurose and Keith Ross. 
# It was modified for use in CSC249: Networks at Smith College by R. Jordan Crouser in Fall 2022

from socket import *
from ICMPpinger import checksum
import os
import sys
import struct
import time
import select 
import binascii

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 2

# The packet that we shall send to each router along the path is the ICMP echo
# request packet, which is exactly what we had used in the ICMP ping exercise.
# We shall use the same packet that we built in the Ping exercise
def build_packet():
    # In the sendOnePing() method of the ICMP Ping exercise, firstly the header of our
    # packet to be sent was made, secondly the checksum was appended to the header and
    # then finally the complete packet was sent to the destination.

    #---------------#
    # Fill in start #
    #---------------#

    # STEP 1: Make the header in a similar way to the ping exercise.
    # STEP 2: Append checksum to the header.
    # Solution can be implemented in 10 lines of Python code.

    myChecksum = 0 #initialize the checksum to zero, will be one of the arguments packed into the header

    ID = os.getpid() & 0xFFFF  #oxFFFF is 16 bits, gest the process ID 

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1) # STEP 1: packs up the header in similiar fashion as ping exercise
    data = struct.pack("d", time.time()) #packs up the time

    myChecksum = checksum(''.join(map(chr, header + data))) # STEP 2:join the header and data, then apply the checksum

    if sys.platform == 'darwin': #despite using a windows, it is good to have this for people who want to run the code and are on mac
        myChecksum = htons(myChecksum) & 0xffff #converts to bytes with oxffff as 16 bits
    else: #windows people 
        myChecksum = htons(myChecksum) #converts to bytes

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)

    #-------------#
    # Fill in end #
    #-------------#

    # Don’t send the packet yet , just return the final packet in this function.
    packet = header + data
    return packet

def get_route(hostname):
    timeLeft = TIMEOUT
    for ttl in range(1,MAX_HOPS):
        for tries in range(TRIES):
            destAddr = gethostbyname(hostname)

            #---------------#
            # Fill in start #
            #---------------#

            # TODO: Make a raw socket named mySocket
            # Solution can be implemented in 2 lines of Python code.

            icmp = getprotobyname("icmp") #getprotobyname from socket module to get the protocol number with icmp
            mySocket = socket(AF_INET, SOCK_RAW, icmp) #creates a raw socket with AF_INET(will use IPv4), SOCK_RAW(will be a raw socket), icmp (protocol number)
            #-------------#
            # Fill in end #
            #-------------#

            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)

            try:
                d = build_packet()
                mySocket.sendto(d, (hostname, 0))
                t= time.time()
                startedSelect = time.time()
                timeLeft = max(0, timeLeft)

                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)

                if whatReady[0] == []: # Timeout
                    print(" * * * Request timed out.")

                recvPacket, addr = mySocket.recvfrom(1024)
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect

                if timeLeft <= 0:
                    #print(" * * * Request timed out.")
                    print(" * * * Request timed out. IP: {}".format(addr[0]))  # Print the IP associated with the timeout

            except timeout:
                
                continue

            else:
                #---------------#
                # Fill in start #
                #---------------#

                    #TODO: Fetch the icmp type from the IP packet
                    # Solution can be implemented in 2 lines of Python code.
                types, _, _, _, _ = struct.unpack("bbHHh", recvPacket[20:28]) #unpack binary data from the packet, tuple into individual variables
                #-------------#
                # Fill in end #
                #-------------#
                
                if types == 11:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 +bytes])[0]
                    print(" %d rtt=%.0f ms %s" %(ttl, (timeReceived -t)*1000, addr[0]))

                elif types == 3:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    print(" %d rtt=%.0f ms %s" %(ttl, (timeReceived-t)*1000, addr[0]))

                elif types == 0:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    print(" %d rtt=%.0f ms %s" %(ttl, (timeReceived - timeSent)*1000, addr[0]))
                    return

                else:
                    print("error")

                break

            finally:
                mySocket.close()

if __name__ == "__main__":

    List = ["192.33.12.201", "128.2.42.52", 
            "35.232.19.139", "66.39.95.22",
            "67.225.164.122", "129.194.6.50",
            "34.174.121.15", "141.20.5.188",
            "134.21.80.50", "128.232.132.8"
            ] #list of IP addresses to test 
    
    for address in List:
        print(f"\nThe traceroute for {address}:\n") #prints the traceroute for each address in IPList
        get_route(address) #get_route function for each address

