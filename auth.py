#!/usr/bin/python3
from scapy.all import *
from threading import Thread
from time import sleep
import hmac,hashlib,binascii
import random
from sys import argv


def get_random_mac(l=6):
    return ':'.join(list(map(lambda x:"%02x"%int(random.random()*0xff),range(l))))

IFACE = 'wlan1'
conf.iface = IFACE
target = argv[1]
source = "00:"+get_random_mac(5)
essid = argv[2]
password = argv[3]
WAIT = 15

beacon = None
def get_beacon():
    def handle(p):
        global beacon
        seen_receiver = p[Dot11].addr1
        seen_sender = p[Dot11].addr2
        seen_bssid = p[Dot11].addr3
        if target.lower() == seen_bssid.lower() and \
        Dot11Beacon in p:
            beacon = p
            print("[*] Beacon from Source {}".format(seen_bssid))
            return True
    sniff(iface=IFACE, lfilter=lambda p: p.haslayer(Dot11Beacon), stop_filter=handle, timeout=WAIT)

is_auth_found = False
def get_authorization_response():
    def handle(p):
        global is_auth_found
        seen_receiver = p[Dot11].addr1
        seen_sender = p[Dot11].addr2
        seen_bssid = p[Dot11].addr3

        if target.lower() == seen_bssid.lower() and \
        target.lower() == seen_sender.lower() and \
        source.lower() == seen_receiver.lower():
            is_auth_found = True
            print("[*] Detected Authentication from Source {0}".format(seen_bssid))
        return is_auth_found
    sniff(iface=IFACE, lfilter=lambda p: p.haslayer(Dot11Auth), stop_filter=handle, timeout=WAIT)

is_assoc_found = False
def get_association_response():
    def handle(p):
        global is_assoc_found
        seen_receiver = p[Dot11].addr1
        seen_sender = p[Dot11].addr2
        seen_bssid = p[Dot11].addr3

        if target.lower() == seen_bssid.lower() and \
        target.lower() == seen_sender.lower() and \
        source.lower() == seen_receiver.lower():
            is_assoc_found = True
            print("[*] Detected Association Response from Source {0}".format(seen_bssid))
        return is_assoc_found
    sniff(iface=IFACE, lfilter=lambda p: p.haslayer(Dot11AssoResp), stop_filter=handle, timeout=WAIT)

anonce = ""
def get_m1():
    def handle(p):
        global anonce
        seen_receiver = p[Dot11].addr1
        seen_sender = p[Dot11].addr2
        seen_bssid = p[Dot11].addr3
        key_mic_is_set = 0b100000000
        if target.lower() == seen_bssid.lower() and \
        target.lower() == seen_sender.lower() and \
        source.lower() == seen_receiver.lower() and \
        not int.from_bytes(bytes(p[EAPOL].payload)[1:3], byteorder='big') & key_mic_is_set:
            anonce = bytes(p[EAPOL].payload)[13:13+32]
            print("[*] EAPOL M1 from Source {}".format(seen_bssid))
            return True
    sniff(iface=IFACE, lfilter=lambda p: p.haslayer(EAPOL), stop_filter=handle, timeout=WAIT)

amic = ""
def get_m3():
    def handle(p):
        global amic
        seen_receiver = p[Dot11].addr1
        seen_sender = p[Dot11].addr2
        seen_bssid = p[Dot11].addr3
        key_mic_is_set = 0b100000000
        if target.lower() == seen_bssid.lower() and \
        target.lower() == seen_sender.lower() and \
        source.lower() == seen_receiver.lower() and \
        int.from_bytes(bytes(p[EAPOL].payload)[1:3], byteorder='big') & key_mic_is_set:
            amic = bytes(p[EAPOL].payload)[77:77+16]
            print("[*] EAPOL M3 from source {}".format(seen_bssid))
            return True
    sniff(iface=IFACE, lfilter=lambda p: p.haslayer(EAPOL), stop_filter=handle, timeout=WAIT)


Thread(target=get_beacon).start()
wait = 5
while not beacon and wait > 0:
    sleep(0.01)
    wait -= 0.01
if beacon:
    print("[+] beacon received")
else:
    print("[-] no beacon received")
    exit(1)

authorization_request = RadioTap()/Dot11(proto=0, FCfield=0, subtype=11, addr2=source, addr3=target, addr1=target, SC=0, type=0)\
    / Dot11Auth(status=0, seqnum=1, algo=0)

Thread(target=get_authorization_response).start()
sleep(0.01)
sendp(authorization_request, verbose=0, count=1)
wait = WAIT
while not is_auth_found and wait > 0:
    sleep(0.01)
    wait -= 0.01
if is_auth_found:
    print("[+] authenticated")
else:
    print("[-] no authenticated")
    exit(1)

tagges_parameters = Dot11Elt(ID='SSID',info=essid, len=len(essid))#/Dot11Elt(ID=36, len=10, info=b'\x24\x01\x28\x01\x2c\x01\x30\x01\x34\x01') 
layer = beacon[Dot11Beacon].payload
rsn_cap = None
while True:
    if not layer:
        break
    if layer.ID == 48:
        the_layer = layer.copy()
        the_layer.remove_payload()
        rsn_cap = the_layer
    layer = layer.payload

'''
association_request = RadioTap() / Dot11(proto=0, FCfield=0, subtype=0, addr2=source, addr3=target, addr1=target, SC=0, type=0) \
    / Dot11AssoReq(listen_interval=1, cap=0x1101) \
    / Dot11Elt(ID=33, len=2, info=b"\x08\x1b") \
    / Dot11Elt(ID=36, len=50, info=b"\x24\x01\x28\x01\x2c\x01\x30\x01\x34\x01\x38\x01\x3c\x01\x40\x01\x64\x01\x68\x01\x6c\x01\x70\x01\x74\x01\x78\x01\x7c\x01\x80\x01\x84\x01\x88\x01\x8c\x01\x90\x01\x95\x01\x99\x01\x9d\x01\xa1\x01\xa5\x01") \
    / Dot11Elt(ID=45, len=26, info=b"\x6f\x01\x13\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00") \
    / Dot11Elt(ID=59, len=20, info=b"\x7c\x51\x53\x54\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82") \
    / Dot11Elt(ID=127, len=8, info=b"\x00\x00\x00\x00\x00\x00\x00\x40") \
    / Dot11Elt(ID=191, len=12, info=b"\x12\x71\x80\x33\xfe\xff\x86\x01\xfe\xff\x86\x01") \
    / Dot11Elt(ID=221, len=7, info=b"\x00\x50\xf2\x02\x00\x01\x00") \
    / Dot11Elt(ID=221, len=8, info=b"\x8c\xfd\xf0\x01\x01\x02\x01\x00") \
    / tagges_parameters
'''

association_request = RadioTap() / Dot11(proto=0, FCfield=0, subtype=0, addr2=source, addr3=target, addr1=target, SC=0, type=0) \
    / Dot11AssoReq(listen_interval=5, cap=0x1101) \
    / beacon[Dot11Beacon].payload

'''
supported_rates = b'\x8c\x12\x98\x24\xb0\x48\x60\x6c'
#supported_rates = b'\x02\x04\x0b\x16\x0c\x12\x18\x24'
association_request = RadioTap() / Dot11(proto=0, FCfield=0, subtype=0, addr2=source, addr3=target, addr1=target, SC=0, type=0) \
    / Dot11AssoReq(listen_interval=5, cap=0x1101) \
    / Dot11Elt(ID=0, len=len(essid), info=essid) \
    / Dot11Elt(ID=1, len=8, info=supported_rates) \
    / Dot11Elt(ID=33, len=2, info=b'\x08\x1b') \
    / Dot11Elt(ID=36, len=10, info=b'\x24\x01\x28\x01\x2c\x01\x30\x01\x34\x01') \
    / Dot11Elt(ID=45, len=26, info=b'\x6f\x01\x13\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00') \
    / Dot11Elt(ID=48, len=20, info=b'\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x00\x00')
'''

Thread(target=get_association_response).start()
Thread(target=get_m1).start()
Thread(target=get_m3).start()
sleep(0.01)
sendp(association_request, verbose=0, count=1)
wait = WAIT
while (not is_assoc_found or not anonce) and wait > 0:
    sleep(0.01)
    wait -= 0.01
if is_assoc_found or anonce:
    print("[+] associated")
else:
    print("[-] no associated")
    exit(1)

wait = WAIT
while not anonce and wait > 0:
    sleep(0.01)
    wait -= 0.01
if anonce:
    print("[+] M1 ANonce: {0}".format(anonce.hex()))
else:
    print("[-] no M1 received")
    exit(1)

def assemble_EAP_Expanded(self, l):
    ret = ''
    for i in range(len(l)):
        if l[i][0] & 0xFF00 == 0xFF00:
            ret += (l[i][1])
        else:
            ret += pack('!H', l[i][0]) + pack('!H', len(l[i][1])) + l[i][1]
    return ret


def PRF_512(key,A,B):
    return b''.join(hmac.new(key,A+chr(0).encode()+B+chr(i).encode(),hashlib.sha1).digest() for i in range(4))[:64]

def get_rand(n):
    o = b''
    for _ in range(n):
        o += int(random.random()*255).to_bytes(1, 'big')
    return o

def b(mac):
    o = b''
    for m in mac.split(':'):
        o += int(m, 16).to_bytes(1, 'big')
    return o

pmk = hashlib.pbkdf2_hmac('sha1', password.encode(), essid.encode(), 4096, 32)
snonce = get_rand(32)
ptk = PRF_512(pmk, b"Pairwise key expansion", min(b(target),b(source))+max(b(target),b(source))+min(anonce,snonce)+max(anonce,snonce))
kck = ptk[0:16]
print("[*] PTK: {}".format(ptk.hex()))
print("[*] KCK: {}".format(kck.hex()))

eapol_data_4 = bytearray(117)
eapol_data_4[0:1] = b"\x02" # Key Description Type: EAPOL RSN Key
eapol_data_4[1:1+2] = b"\x01\x0a" # Key Information: 0x010a
eapol_data_4[3:3+2] = b"\x00\x00" # Key Length: 0
eapol_data_4[5:5+8] = b"\x00\x00\x00\x00\x00\x00\x00\x01" # Replay Counter: 1
eapol_data_4[13:13+32] = snonce # WPA Key Nonce
eapol_data_4[45:45+16] = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" # WPA Key IV
eapol_data_4[61:61+8] = b"\x00\x00\x00\x00\x00\x00\x00\x00" # WPA Key RSC
eapol_data_4[69:69+8] = b"\x00\x00\x00\x00\x00\x00\x00\x00" # WPA Key ID
eapol_data_4[77:77+16] = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" # WPA Key MIC
eapol_data_4[93:93+2] = b"\x00\x16" # WPA Key Data Length: 22
eapol_data_4[95:95+26] = bytes(rsn_cap) # WPA Key Data Length

mic = hmac.new(kck, b"\x01\x03\x00\x75" + bytes(eapol_data_4[:77]) + bytes.fromhex("00000000000000000000000000000000") + bytes(eapol_data_4[93:]), hashlib.sha1).digest()[0:16]
eapol_data_4[77:77+16] = mic
print("[*] MIC: {}".format(mic.hex()))

m2 = RadioTap() / Dot11(proto=0, FCfield=1, addr2=source, addr3=target, addr1=target, subtype=8, SC=0, type=2, ID=55808) \
    / Dot11QoS(TID=6, TXOP=0, EOSP=0) \
    / LLC(dsap=0xaa, ssap=0xaa, ctrl=0x3) \
    / SNAP(OUI=0, code=0x888e) \
    / EAPOL(version=1, type=3, len=117) / bytes(eapol_data_4)

def checksum(data):
    FSC = binascii.crc32(data) % (1<<32)
    FSC = str(hex(FSC))[2:]
    FSC = "0" * (8-len(FSC)) + FSC
    return bytes.fromhex(FSC)[::-1]

m2 /= checksum(bytes(m2))
sendp(m2, verbose=0, count=1)
wait = 1.0
while not amic and wait > 0:
    sleep(0.01)
    wait -= 0.01

if amic:
    print("[+] M3 AMIC: {0}".format(amic.hex()))
    exit(0)
else:
    exit(1)


# -> authentication request
# <- authentication response
# -> association request
# <- association response
# <- EAPOL M1
# -> EAPOL M2
#https://www.duckware.com/tech/verify-mic-in-four-way-handshake.py.txt
