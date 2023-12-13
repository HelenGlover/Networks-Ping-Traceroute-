# Attribution: this assignment is based on ICMP Pinger Lab from Computer Networking: a Top-Down Approach by Jim Kurose and Keith Ross. 
# It was modified for use in CSC249: Networks at Smith College by R. Jordan Crouser in Fall 2022, and by Brant Cheikes for Fall 2023.

from socket import *
import os
import sys 
import struct 
import time 
import select 
import binascii


ICMP_ECHO_REQUEST = 8

# -------------------------------------
# This method takes care of calculating
#   a checksum to make sure nothing was
#   corrupted in transit.
#  
# You do not need to modify this method
# -------------------------------------

#checksum = calculates 16 bit 
def checksum(string): 
    csum = 0
    countTo = (len(string) // 2) * 2  #number of pairs 
    count = 0

    while count < countTo: #processes the string two characters at a time with ASCII (uses ord function for unicode)
        thisVal = ord(string[count+1]) * 256 + ord(string[count]) 
        csum = csum + thisVal
        csum = csum & 0xffffffff 
        count = count + 2

    if countTo < len(string): #if length of the string is odd, last character is processed alone
        csum = csum + ord(string[len(string) - 1]) 
        csum = csum & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)  #added for 32
    csum = csum + (csum >> 16)

    answer = ~csum

    answer = answer & 0xffff
 
    answer = answer >> 8 | (answer << 8 & 0xff00) 
    return answer


def receiveOnePing(mySocket, ID, timeout, destAddr): 
    
    timeLeft = timeout
    
    while True:
        startedSelect = time.time()

        whatReady = select.select([mySocket], [], [], timeLeft) 
        howLongInSelect = (time.time() - startedSelect)
        if whatReady[0] == []: # If one second goes by without a reply from the server - loss/server down
            return "Request timed out."

        timeReceived = time.time()
        recPacket, addr = mySocket.recvfrom(1024) # retrive packet from socket

        #---------------#
        # Fill in start #
        #---------------#
        icmpHeader = recPacket[20:28] #extract the header from the packet, header starts at byte 20 and extends 8 bytes
        type, code, checksum, packetID, sequence = struct.unpack("bbHHh", icmpHeader) #unpacks the header, returns a tuple of values
        
        if type == 0 and code == 0 and packetID == ID: #packet has type 0 and packetID is the same as ID
            bytesForDouble = struct.calcsize("d") # caclualte # of bytes to store the double 
            timeSent = struct.unpack("d", recPacket[28:28 + bytesForDouble])[0] #unpacks the time sent from the packet, calls bytesForDouble
            rtt = timeReceived - timeSent #time recieved from recieveoneping
            return f"{rtt:.6f}" #returns rtt and limits the number of decimal places to 6. Output looks cleaner 
        #-------------#
        # Fill in end #
        #-------------#

        timeLeft = timeLeft - howLongInSelect 
        
        if timeLeft <= 0:
            return "Request timed out." # If packet is not received back from server, return "timed out."

# to send single ping to destination 

def sendOnePing(mySocket, destAddr, ID):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    myChecksum = 0

    # Make a dummy header with a 0 checksum
 
    # struct - PACKS A LIST OF VALUES INTO THE STRING 
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1) #ICMP header using struct.pack to create binary string with different bits 
    data = struct.pack("d", time.time()) #time as float in the string

    # Calculate the checksum on the data and the dummy header. 
    myChecksum = checksum(''.join(map(chr, header+data)))

    # Get the right checksum, and put in the header 
    if sys.platform == 'darwin':  #ONLY FOR MAC -  Darwin for Mac OS X
        # Convert 16-bit integers from host to network byte order 
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1) #update with new checksum
    packet = header + data #concenates the header and data into one packet

    mySocket.sendto(packet, (destAddr, 1)) # AF_INET address must be tuple, not str 
    # Both LISTS and TUPLES consist of a number of objects
    # which can be referenced by their position number within the object.

def doOnePing(destAddr, timeout): 
    icmp = getprotobyname("icmp") 

    # SOCK_RAW is a powerful socket type. For more details:	http://sock-raw.org/papers/sock_raw. Creates a raw sock for sending ICMP packets
    mySocket = socket(AF_INET, SOCK_RAW, icmp)

    myID = os.getpid() & 0xFFFF # Return the current process i 
    sendOnePing(mySocket, destAddr, myID) #send echo request/pong to destination 
    delay = receiveOnePing(mySocket, myID, timeout, destAddr) #used to send the ping, for RTT calculations 
 
    mySocket.close() #close socket
    return delay 

def ping(host, timeout=1, repeat=3):

    # timeout=1 means: If one second goes by without a reply from the server,
    # the client assumes that either the client's ping or the server's pong is lost 

    dest = gethostbyname(host) #get the host name from the command line
    print(f"Pinging {host} [{dest}] {repeat} times using Python:")

    # Send ping requests to a server separated by approximately one second 
    # Do this only a fixed number of times as determined by 'repeat' argument
    numPings = 1
    while (numPings <= repeat) :
        delay = doOnePing(dest, timeout) 
        print(f"Ping {numPings} RTT {delay} sec")
        time.sleep(1) # one second between ping reuqests 
        numPings += 1
    return delay


if __name__ == "__main__":

    List = ["192.33.12.201", "128.2.42.52", 
            "35.232.19.139", "66.39.95.22",
            "67.225.164.122", "129.194.6.50",
            "34.174.121.15", "141.20.5.188",
            "134.21.80.50", "128.232.132.8"
            ] #list of IP addresses to test 

    for address in List:
        ping(address) #get_route function for each address