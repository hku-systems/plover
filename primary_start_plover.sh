#!/bin/bash
# this script should be put on the remote machine

# Step 1. Export absolute path to vm-ft
export VMFT_ROOT=/home/hkucs/vm-ft

# Step 2. Start qemu (primary machine side)

cd vm-ft/qemu/

sudo killall -9 qemu-system-x86_64

sleep 3

sudo LD_LIBRARY_PATH=$VMFT_ROOT/rdma-paxos/target:$LD_LIBRARY_PATH x86_64-softmmu/qemu-system-x86_64 -enable-kvm -boot c -m 2048 -smp 4 \
-qmp stdio -vnc :7 -name primary -cpu qemu64,+kvmclock \
-drive if=virtio,id=colo-disk0,driver=quorum,read-pattern=fifo,vote-threshold=1,children.0.file.filename=/home/hkucs/ubuntu-ye-cms.img,children.0.driver=raw -S \
-netdev tap,id=hn0,vhost=off,script=/etc/qemu-ifup,downscript=/etc/qemu-ifdown -device e1000,id=e0,netdev=hn0,mac=52:a4:00:12:78:66 -global kvm-apic.vapic=false \
-qmp tcp:localhost:4444,server,nowait
