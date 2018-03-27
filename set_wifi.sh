#!/bin/bash

ifconfig wlx502b73e83bf2 down
iw dev wlx502b73e83bf2 set monitor otherbss fcsfail
#iwconfig wlx502b73e83bf2 mode monitor
ifconfig wlx502b73e83bf2 up
iwconfig wlx502b73e83bf2 channel 13
./fpv_tx -b 8 -r 4 -f 1024 wlx502b73e83bf2