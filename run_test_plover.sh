#!/bin/bash
secondary_ip=10.22.1.1

set -e # exit when error
set -x # debug mode
echo "please make sure two machines have been started and election finished"

# some settings for libnl
# libnl setting for secondary
ssh hkucs@$secondary_ip "sudo modprobe ifb numifbs=100"
ssh hkucs@$secondary_ip "sudo ip link set up ifb0"
ssh hkucs@$secondary_ip "sudo tc qdisc add dev tap0 ingress"
ssh hkucs@$secondary_ip "sudo tc filter add dev tap0 parent ffff: proto ip pref 10 u32 match u32 0 0 action mirred egress redirect dev ifb0"
# libnl setting for primary
sudo modprobe ifb numifbs=100  # (or some large number)
sudo ip link set up ifb0  # <= corresponds to tap device 'tap0'
sudo tc qdisc add dev tap0 ingress
sudo tc filter add dev tap0 parent ffff: proto ip pref 10 u32 match u32 0 0 action mirred egress redirect dev ifb0
sleep 5

# some settings in secondary machine qemu monitor
ssh hkucs@$secondary_ip "\
(\
echo {\'execute\':\'qmp_capabilities\'};\
echo {\'execute\': \'nbd-server-start\', \'arguments\': {\'addr\': {\'type\': \'inet\', \'data\': {\'host\': \'10.22.1.1\', \'port\': \'8889\'} } }};\
echo {\'execute\': \'nbd-server-add\', \'arguments\': {\'device\': \'colo-disk0\', \'writable\': true } };\
sleep 10;\
) | telnet localhost 4444"

# some settings in primary machine qemu monitor
(
echo "{'execute':'qmp_capabilities'}"
echo "{ 'execute': 'human-monitor-command','arguments': {'command-line': 'drive_add -n buddy driver=replication,mode=primary,file.driver=nbd,file.host=10.22.1.1,file.port=8889,file.export=colo-disk0,node-name=node0'}}"
echo "{ 'execute':'x-blockdev-change', 'arguments':{'parent': 'colo-disk0', 'node': 'node0' } }"
echo "{ 'execute': 'migrate-set-capabilities', 'arguments': {'capabilities': [ {'capability': 'x-colo', 'state': true } ] } }"
echo "{ 'execute': 'migrate', 'arguments': {'uri': 'tcp:10.22.1.1:8888' } }"
#debug mode
#echo "{ 'execute': 'migrate-set-parameters' , 'arguments': { 'x-checkpoint-delay': 20000 } }"
sleep 10;
) | telnet localhost 4444

