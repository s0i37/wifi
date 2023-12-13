#!/bin/bash

RED='\x1b[31m'
YELLOW='\x1b[93m'
GREEN='\x1b[32m'
CYAN='\x1b[96m'
BLUE='\x1b[34m'
GREY='\x1b[90m'
RESET='\x1b[0m'
[ -z "$IFACE" ] && IFACE='wlan0'

[[ $# -ge 1 ]] && interval="$1" || interval=15

sudo ifconfig $IFACE up
while :; do
    date +'%H:%M:%S %d.%m.%Y'
    sudo iw dev $IFACE scan | egrep '^BSS|SSID:|freq:|signal:|TSF:|Authentication|WPS:|set: channel' | while read line
    do #echo -e "$line"
      if echo "$line" | egrep -q '^BSS' && [ -n "$ap" ]; then
	vendor=$(mac_vendor_lookup $ap | grep -v 'Prefix is not registered')
	echo -e "$ap [${YELLOW}$vendor${RESET}] ${CYAN}$essid${RESET} ${BLUE}$signal${RESET} $channel $auth (${RED}$wps${RESET})"
	ap=''; essid=''; auth=$RED'OPN'$RESET; wps=''
      fi
      if echo "$line" | egrep -q '^BSS'; then
        ap=$(echo "$line" | egrep '^BSS' | awk '{print $2}' | cut -d '(' -f 1)
      elif echo "$line" | grep -q 'SSID:'; then
	read _ essid <<< $(echo "$line" | grep 'SSID:')
      elif echo "$line" | grep -q 'freq:'; then
	freq=$(echo "$line" | grep 'freq:' | awk '{print $2}')
      elif echo "$line" | grep -q 'signal:'; then
	signal=$(echo "$line" | grep 'signal:' | awk '{print $2}' | cut -d '.' -f 1)
      elif echo "$line" | grep -q 'TSF:'; then
	uptime=$(echo "$line" | grep 'TSF:' | awk '{print $4 " " $5}')
      elif echo "$line" | grep -q 'Authentication'; then
	if echo "$line" | grep -q '802.1'; then
	  auth=$RED'EAP'$RESET
	elif echo "$line" | grep -q 'PSK'; then
	  auth=$GREEN'WPA'$RESET
	fi
      elif echo "$line" | grep -q 'WPS:'; then
	read _ _ wps <<< $(echo "$line" | grep 'WPS:')
      elif echo "$line" | grep -q 'set: channel'; then
        channel=$(echo "$line" | grep 'set: channel' | awk '{print $5}')
      fi
    done
    echo ''
    sleep "$interval"
done

