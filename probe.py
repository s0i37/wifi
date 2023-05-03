#!/usr/bin/python3
from scapy.all import *
from sys import argv

iface = argv[1]
essid = argv[2]

OPN = 0x2104
WPA = 0x3104

def probe_request(essid):
	source = "00:C0:CA:AE:BE:A1"
	target = "ff:ff:ff:ff:ff:ff"
	radio = RadioTap()
	probe = Dot11(subtype=4, addr1=target, addr2=source, addr3=source, SC=0x3060)/\
	 Dot11ProbeReq()/\
	 Dot11Elt(ID='SSID', info=essid)/\
	 Dot11Elt(ID='Rates', info=b'\x8c\x12\x98\x24\xb0\x48\x60\x6c')/\
	 Dot11Elt(ID='DSset', info=int(36).to_bytes(1,'big'))
	return srp1(radio/probe, iface=iface, timeout=1.0)
	#wrpcap("probe.pcap", radio/probe)

def probe_response(essid):
	source = "00:C0:CA:AE:BE:A1"
	target = "80:32:53:74:d5:a6"
	#radio = RadioTap(len=18, present=0x482e,Rate=2,Channel=2412,ChannelFlags=0x00a0,dBm_AntSignal=chr(77),Antenna=1)
	radio = RadioTap()
	probe = Dot11(subtype=5, addr1=target, addr2=source, addr3=source, SC=0x3060)/\
	 Dot11ProbeResp(timestamp=123123123, beacon_interval=0x0064, cap=OPN)/\
	 Dot11Elt(ID='SSID', info=essid)/\
	 Dot11Elt(ID='Rates', info=b'\x8c\x12\x98\x24\xb0\x48\x60\x6c')/\
	 Dot11Elt(ID='DSset', info=int(36).to_bytes(1,'big'))
	sendp(radio/probe, iface=iface, inter=0.1, count=500, loop=1)
	#wrpcap("probe.pcap", radio/probe)

probe_request(essid)
#probe_response(essid)
