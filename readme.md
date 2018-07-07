## How to setup/test COLO

Tested using Ubuntu 16.04.2 (64bit), MLNX_OFED_LINUX-3.4-2.0.0.0-ubuntu16.04-x86_64

### Test environment prepare
```
# export VMFT_ROOT=<absolute path of vm-ft>
```
- Install MLNX_OFED driver

- RDMA Paxos
```
# install libev libdb libconfig
# cd rdma-paxos/target
# make
```
- Qemu colo
```
# cd qemu
# apt-get install zlib1g-dev libglib2.0-dev libpixman-1-dev libgnutls-dev
# dpkg -i dep-lib/*.deb
# ./configure --disable-werror --target-list=x86_64-softmmu --extra-ldflags="-Wl,--no-as-needed -lnl-3 -lnl-cli-3 -lnl-route-3 -lnl-3 -lnl-cli-3 -lnl-route-3 -L$VMFT_ROOT/rdma-paxos/target -linterpose" --extra-cflags="-I$VMFT_ROOT/rdma-paxos/src/include/rsm-interface -I/usr/include/libnl3"
```

- Set Up the Bridge and network environment

- Qemu-ifup/Qemu-ifdown
```
Primary:
root@master# mv qemu-ifup qemu-ifdown /etc/
Secondary:
like Primary side
```

### Test steps
**Note: Please change the ip address in sh file.**

- *Primary side:*
```
# primary_start_plover.sh
```

- *Secondary side:*
```
# qemu-img create -f qcow2 /mnt/ramfs/active_disk.img 10G

# qemu-img create -f qcow2 /mnt/ramfs/hidden_disk.img 10G

# secondary_start_plover.sh
```

- *Sentinel side:*
```
# sentinel_start_plover.sh
```

- *Primary side:*
```
# run_test_plover.sh
```

***Note:***

*a. Active disk, hidden disk and nbd target's length should be the same.*
