#!/bin/bash
# primary machine #3:
# hkucs@202.45.128.162
# this script should be put on the remote machine

cd qemu-mc

sudo killall -9 qemu-system-x86_64

sleep 3

sudo x86_64-softmmu/qemu-system-x86_64 /local/ubuntu/ubuntu-ye-cms.img -m 2048 -smp 16 --enable-kvm -netdev tap,id=net0,ifname=tap0,script=/etc/qemu-ifup,downscript=no -device e1000,netdev=net0,mac=ba:79:03:4e:35:87 -vnc :7 \
-monitor telnet::4444,server,nowait

