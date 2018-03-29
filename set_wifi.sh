#!/bin/bash

WLAN=wlx0013ef60052d

ifconfig $WLAN down
iw dev $WLAN set monitor otherbss fcsfail
#iwconfig $WLAN mode monitor
ifconfig $WLAN up
iwconfig $WLAN channel 13
./fpv_tx -b 8 -r 4 -f 1024 $WLAN