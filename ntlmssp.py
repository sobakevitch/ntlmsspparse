print "You probably want rewrite.py, not this file"
import sys;sys.exit()
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import binascii
import base64
import socket
import sys
import struct
if len(sys.argv) != 2:
    print "Usage:\n\t%s <file>.pcap" % sys.argv[0]
    print "\nIt's probably best to run:\n\ttshark -r <infile.pcap> 'ntlmssp.ntlmserverchallenge or ntlmssp.ntlmclientchallenge [and http]' -w <outfile.pcap>'"
    print "where [and http] is optional but recommended"
    sys.exit(1)

def decode_ntlmssp_client(ntlmssp_raw):
    ntlmssp=ntlmssp_raw[12:]
    #!h!h!q!h!h!q!h!h!q!h!h!q!qiq
    lmlen,lmmax,lmoff,ntlen,ntmax,ntoff,domlen,dommax,domoff,userlen,usermax,useroff,hostlen,hostmax,hostoff,sesskey,flags,vers=struct.unpack("hhihhihhihhihhiqiq",ntlmssp[:64])

    #lm=ntlmssp[:8]
    #ntlmssp=ntlmssp[8:]
    #lmlen=socket.ntohs(int(binascii.hexlify(lm[:2]),16))
    #lmmax=socket.ntohs(int(binascii.hexlify(lm[2:4]),16))
    #lmoff=socket.ntohl(int(binascii.hexlify(lm[4:]),16))
    #nt=ntlmssp[:8]
    #ntlmssp=ntlmssp[8:]
    #ntlen=socket.ntohs(int(binascii.hexlify(nt[:2]),16))
    #ntmax=socket.ntohs(int(binascii.hexlify(nt[2:4]),16))
    #ntoff=socket.ntohl(int(binascii.hexlify(nt[4:]),16))
    #dom=ntlmssp[:8]
    #ntlmssp=ntlmssp[8:]
    #domlen=socket.ntohs(int(binascii.hexlify(dom[:2]),16))
    #dommax=socket.ntohs(int(binascii.hexlify(dom[2:4]),16))
    #domoff=socket.ntohl(int(binascii.hexlify(dom[4:]),16))
    #user=ntlmssp[:8]
    #ntlmssp=ntlmssp[8:]
    #userlen=socket.ntohs(int(binascii.hexlify(user[:2]),16))
    #usermax=socket.ntohs(int(binascii.hexlify(user[2:4]),16))
    #useroff=socket.ntohl(int(binascii.hexlify(user[4:]),16))
    #host=ntlmssp[:8]
    #ntlmssp=ntlmssp[8:]
    #hostlen=socket.ntohs(int(binascii.hexlify(host[:2]),16))
    #hostmax=socket.ntohs(int(binascii.hexlify(host[2:4]),16))
    #hostoff=socket.ntohl(int(binascii.hexlify(host[4:]),16))
    #sesskey=ntlmssp[:8]
    #ntlmssp=ntlmssp[8:]
    #flags=ntlmssp[:4]
    #ntlmssp=ntlmssp[4:]
    #vers=ntlmssp[:8]
    #ntlmssp=ntlmssp[8:]
    username=ntlmssp_raw[useroff:useroff+userlen].replace('\0','')
    domain=ntlmssp_raw[domoff:domoff+domlen].replace('\0','')
    nthash=binascii.hexlify(ntlmssp_raw[ntoff:ntoff+ntlen])
    lmhash=binascii.hexlify(ntlmssp_raw[lmoff:lmoff+lmlen])
    chall=binascii.hexlify(ntlmssp_raw[hostoff+hostlen:hostoff+hostlen+8])
    #print (lmlen,lmmax,lmoff,ntlen,ntmax,ntoff,domlen,dommax,domoff,userlen,usermax,useroff,hostlen,hostmax,hostoff,sesskey,flags,vers)
    return [username,domain,nthash,lmhash]

def decode_ntlmssp_server(ntlmssp_raw):
    ntlmssp=ntlmssp_raw[24:32]
    chall=binascii.hexlify(ntlmssp)
    return chall

def getntlmssp_raw(packet):
    if packet['Raw'].load[5:8] == 'SMB':
        ntlmssp_raw=packet['Raw'].load[packet['Raw'].load.index('NTLMSSP'):]
    elif 'Negot' in packet['Raw'].load:
        ntlmssp_raw=base64.b64decode([i for i in packet['Raw'].load.split('\r\n') if 'Negot' in i][0].split()[2])
    else:
        return "\x00"*12 #stops breakage in decode_ntlmssp
    return ntlmssp_raw

def decode_ntlmssp(packetpair):
    if type(packetpair) != type(list()):
        return -1
    if type(packetpair[0]) != type(Ether()) or type(packetpair[1]) != type(Ether()):
        return -1
    typecheck=socket.ntohl(int(binascii.hexlify(getntlmssp_raw(packetpair[0])[8:12]),16))
    typecheck+=socket.ntohl(int(binascii.hexlify(getntlmssp_raw(packetpair[1])[8:12]),16))
    if typecheck != 5: return -1
    for packet in packetpair:
        ntlmssp_raw=getntlmssp_raw(packet)
        if not ntlmssp_raw:
            return -1
        pkttype=socket.ntohl(int(binascii.hexlify(ntlmssp_raw[8:12]),16))
        if pkttype == 2: #CHALLENGE
            chall=decode_ntlmssp_server(ntlmssp_raw)
        elif pkttype == 3: #AUTH
            username,domain,nthash,lmhash=decode_ntlmssp_client(ntlmssp_raw)
    if len(lmhash) > 48 or len(nthash) > 48:
        return -1
    hashes.append(username+"::"+domain+":"+lmhash+":"+nthash+":"+chall)

def makepairs(packets):
    pairs=[]
    for i,packet in enumerate(packets):
        sys.stderr.write(str('\r'+str(i)+'/'+str(len(packets))))
        srcip=packet['IP'].dst
        srcprt=packet['TCP'].dport
        dstip=packet['IP'].src
        dstprt=packet['TCP'].sport
        otherpacket=[i for i in packets if i['IP'].src == srcip and i['IP'].dst == dstip and i['TCP'].sport == srcprt and i['TCP'].dport == dstprt]
        if len(otherpacket) >= 1:
            otherpacket=otherpacket[0]
        else:
            pairs.append([0,0])
        if len([otherpacket,packet]) == 2:
            pairs.append([otherpacket,packet])
    sys.stderr.write('\n')
    return pairs
        
hashes=[]
print >> sys.stderr, "Loading packets..."
packets=rdpcap(sys.argv[1])
print >> sys.stderr, "Packets Loaded"
print >> sys.stderr, "Making pairs..."
pairs=makepairs(packets)
print >> sys.stderr, "Finished making pairs"
print >> sys.stderr, "Decoding negotiations..."
for i in pairs:
    if i == [0,0] or not i:
        continue
    decode_ntlmssp(i)
print >> sys.stderr, "Negotiations decoded"
hashes=list(set(hashes))
for hash in hashes:
    print hash
#check packets contain NTLMSSP:
