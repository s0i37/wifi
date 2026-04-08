#!/bin/bash

RED='\x1b[31m'
YELLOW='\x1b[93m'
GREEN='\x1b[32m'
CYAN='\x1b[96m'
BLUE='\x1b[34m'
GREY='\x1b[90m'
RESET='\x1b[0m'

[[ $# -ge 1 ]] && filter="$1" || filter=''
[ -z "$IFACE" ] && IFACE='wlan0'
[ -z "$INTERVAL" ] && INTERVAL=0

shopt -s lastpipe
sudo ifconfig $IFACE up
while :; do
  date +'%H:%M:%S %d.%m.%Y'
  { sudo iw dev $IFACE scan | egrep '^BSS|SSID:|freq:|signal:|TSF:|capability:|Authentication|WPS:' | while read -r line
  do #echo -e "$line" >&2
  if echo "$line" | egrep -q '^BSS' && [ -n "$out" ]; then
    echo "$out"
    out=""
  fi
  if echo "$line" | egrep -q 'Authentication|WPS:' && ! echo "$out" | grep -q 'SSID:'; then out+=$'SSID:\t'; fi
  out+="$line"$'\t'
  done; echo "$out"; } | grep -i "$filter" | while IFS=$'\t' read -r ap uptime freq caps signal essid auth wps
  do #echo "ap=$ap, uptime=$uptime, signal=$signal, essid=$essid, channel=$channel, capabilities=$caps, auth=$auth, wps=$wps" >&2
    ap=$(echo "$ap" | awk '{print $2}' | cut -d '(' -f 1)
    vendor=$(mac_vendor_lookup $ap | grep -v 'Prefix is not registered') #pip3 install mac-vendor-lookup
    read -r _ essid <<< $(echo "$essid" | grep 'SSID:')
    freq=$(echo "$freq" | grep 'freq:' | awk '{print $2}')
    signal=$(echo "$signal" | grep 'signal:' | awk '{print $2}' | cut -d '.' -f 1)
    uptime=$(echo "$uptime" | grep 'TSF:' | awk '{print $4 " " $5}')
    if echo "$auth" | grep -q '802.1'; then
      auth=$RED'EAP'$RESET
    elif echo "$auth" | grep -q 'SAE'; then
      auth=$GREEN'WPA3'$RESET
    elif echo "$auth" | grep -q 'PSK'; then
      auth=$GREEN'WPA'$RESET
    elif echo "$caps" | grep -q 'Privacy'; then
      auth=$RED'WEP'$RESET
    else
      auth=$RED'OPN'$RESET
    fi
    if echo "$wps" | grep -q 'WPS:'; then
      wps='WPS'
    else
      wps=''
    fi
    echo -e "$ap [${YELLOW}$vendor${RESET}] ${CYAN}$essid${RESET} ${BLUE}$signal${RESET} $freq $auth ${RED}$wps${RESET}"
  done
  echo ''
  sleep "$INTERVAL"
done
