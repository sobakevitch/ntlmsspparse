#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from sys import argv, exit
from scapy.all import rdpcap, hexdump
import base64
import struct
import binascii
from collections import defaultdict
from struct import unpack
import re

# references
# [0] http://www.innovation.ch/personal/ronald/ntlm.html

REGEX = "(WWW-|Proxy-|)(Authenticate|Authorization): (NTLM|Negotiate)"

if len(argv) != 2:
	print("Usage:\n\t%s <file>.pcap" % argv[0])
	print("\nIt's probably best to run:\n\ttshark -r <infile.pcap> 'ntlmssp.ntlmserverchallenge or ntlmssp.ntlmclientchallenge [and http]' -w <outfile.pcap>'")
	print("where [and http] is optional but recommended")
	exit(1)


REGEXP = (
	"WWW-Authenticate: NTLM",  # HTTP NTLMSSP_CHALLENGE
	"Authorization: NTLM",  # HTTP NTLMSSP_AUTH
	"Proxy-Authenticate: Negotiate",  # Proxy NTLMSSP_CHALLENGE
	"Proxy-Authorization: Negotiate",  # Proxy NTLMSSP_AUTH
	"Proxy-Authenticate: NTLM",  # Proxy NTLMSSP_CHALLENGE
	"Proxy-Authorization: NTLM",  # Proxy NTLMSSP_AUTH
	"NTLMSSP"
)


allpackets = rdpcap(argv[1])
packets = [i for i in allpackets if i.haslayer("TCP") and i.haslayer("Raw") and [x for x in REGEXP if x in i["Raw"].load]]

acks = defaultdict(list)


def store(i):
	acks[i["TCP"].ack].append(i["Raw"].load)


[store(i) for i in allpackets if i.haslayer("TCP") and i.haslayer("Raw")]

# see references[0]

srvchallenge = {}
pairs = []

for packet in packets:  # Frankenstein's state machine and TCP reassembly
	try:
		ntlmsspheader = [i for i in packet['Raw'].load.split('\r\n') if re.match(REGEX, i)][0]
	except IndexError as e:
		raw = packet.load
		idx = raw.find("NTLMSSP") + len("NTLMSSP") + 1
		typ = unpack("<I", raw[idx:idx + 4])[0]
		if typ == 2:  # Type 2: Server challenge
			idx += 16
			srvchallenge[packet["TCP"].ack] = raw[idx: idx + 8]
		elif typ == 3:  # Type 3: Client Auth
			response = raw[raw.find("NTLMSSP"):]
			pairs.append(("NTLMSSP", srvchallenge[packet["TCP"].seq], response))
	else:
		# Type 2: Server challenge
		if any([ntlmsspheader.startswith("WWW-Authenticate: NTLM "), ntlmsspheader.startswith("Proxy-Authenticate: Negotiate"), ntlmsspheader.startswith("Proxy-Authenticate: NTLM")]):
			packets = acks[packet["TCP"].ack]
			srvchallenge[packet["TCP"].ack] = ''.join(packets)
		# Type 3: Client Auth
		if any([ntlmsspheader.startswith("Authorization: NTLM "), ntlmsspheader.startswith("Proxy-Authorization: Negotiate"), ntlmsspheader.startswith("Proxy-Authorization: NTLM")]):
			if srvchallenge.has_key(packet["TCP"].seq):
				packets = acks[packet["TCP"].ack]
				pairs.append(("HTTPNTLMSSP", srvchallenge[packet["TCP"].seq], ''.join(packets)))

for typ, challenge, response in pairs:
	if typ == "HTTPNTLMSSP":
		challenge = [i for i in challenge.split('\r\n') if re.match(REGEX, i)][0]
		response = [i for i in response.split('\r\n') if re.match(REGEX, i)][0]
		challenge = base64.b64decode(challenge.split(' ')[2])
		response = base64.b64decode(response.split(' ')[2])
		serverchallenge = binascii.b2a_hex(challenge[24:32])  # offset to the challenge, 8 bytes long
	else:
		serverchallenge = binascii.b2a_hex(challenge)

	lmlen, lmmax, lmoff, ntlen, ntmax, ntoff, domlen, dommax, domoff, userlen, usermax, useroff = struct.unpack("12xhhihhihhihhi", response[:44])
	lmhash = binascii.b2a_hex(response[lmoff:lmoff + lmlen])
	nthash = binascii.b2a_hex(response[ntoff:ntoff + ntlen])
	domain = response[domoff:domoff + domlen].replace("\0", "")
	user = response[useroff:useroff + userlen].replace("\0", "")
	if ntlen == 24:  # NTLM
		print(user + "::" + domain + ":" + lmhash + ":" + nthash + ":" + serverchallenge)
	else:  # NTLMv2
		print(user + "::" + domain + ":" + serverchallenge + ":" + nthash[:32] + ":" + nthash[32:])
