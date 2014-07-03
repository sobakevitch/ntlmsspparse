import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import base64
import struct
import binascii

#references
#[0] http://www.innovation.ch/personal/ronald/ntlm.html


if len(sys.argv) != 2:
    print "Usage:\n\t%s <file>.pcap" % sys.argv[0]
    print "\nIt's probably best to run:\n\ttshark -r <infile.pcap> 'ntlmssp.ntlmserverchallenge or ntlmssp.ntlmclientchallenge [and http]' -w <outfile.pcap>'"
    print "where [and http] is optional but recommended"
    sys.exit(1)

packets = rdpcap(sys.argv[1])
packets = [i for i in packets if i.haslayer("TCP") and i.haslayer("Raw") and ("WWW-Authenticate: NTLM" in i['Raw'].load or "Authorization: NTLM" in i['Raw'].load)]
#see references[0]
svrchallenge = {}
pairs = []
for packet in packets:
    ntlmsspheader = [i for i in packet['Raw'].load.split('\r\n') if re.match("(WWW-Authenticate|Authorization): NTLM", i)][0]
    if ntlmsspheader.startswith("WWW-Authenticate: NTLM "): #Type 2: Server challenge
        svrchallenge[packet["TCP"].ack] = packet
    if ntlmsspheader.startswith("Authorization: NTLM "): #Type 3: Client Auth
        if svrchallenge.has_key(packet["TCP"].seq):
            pairs.append([svrchallenge[packet["TCP"].seq], packet])

for challenge, response in pairs:
    challenge = [i for i in challenge['Raw'].load.split('\r\n') if re.match("(WWW-Authenticate|Authorization): NTLM", i)][0]
    response = [i for i in response['Raw'].load.split('\r\n') if re.match("(WWW-Authenticate|Authorization): NTLM", i)][0]
    
    try:
        challenge = base64.b64decode(challenge.split(' ')[2])
        response = base64.b64decode(response.split(' ')[2])
    except TypeError:
        #quirk in test file?
        continue
    
    serverchallenge = binascii.b2a_hex(challenge[24:32]) #offset to the challenge, 8 bytes long
    lmlen, lmmax, lmoff, ntlen, ntmax, ntoff, domlen, dommax, domoff, userlen, usermax, useroff = struct.unpack("12xhhihhihhihhi", response[:44])
    nthash = binascii.b2a_hex(response[ntoff:ntoff+ntlen])
    domain = response[domoff:domoff+domlen].replace("\0", "")
    user = response[useroff:useroff+userlen].replace("\0", "")
    print user+"::"+domain+":"+serverchallenge+":"+nthash[:32]+":"+nthash
