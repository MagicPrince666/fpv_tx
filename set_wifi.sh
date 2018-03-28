#!/bin/bash

WLAN=wlx502b73e83bf2

ifconfig $WLAN down
iw dev $WLAN set monitor otherbss fcsfail
#iwconfig wlx502b73e83bf2 mode monitor
ifconfig $WLAN up
iwconfig $WLAN channel 13
./fpv_tx -b 8 -r 4 -f 1024 $WLAN