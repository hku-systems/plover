#!/bin/bash
vm_ip=10.22.1.55
client_ip=10.22.1.1
secondary_ip=10.22.1.1

#set -e # exit when error
#set -x # debug mode
set_libnl=true
set_primary=true
set_secondary=true
run_mysql=false
run_ssdb=false
run_pgsql=false
run_mongoose=false
run_mediatomb=false
run_redis=false
run_tomcat=false
echo "=============================================="
echo "command args:"
echo "-a : setting for primary machine"
echo "-b : setting for secondary machine"
echo "-c : setting for libnl"
echo "-d : mysql"
echo "-e : ssdb"
echo "-f : pgsql"
echo "-g : mongoose"
echo "-i : mediatomb"
echo "-j : redis"
echo "-k : tomcat7"
echo "e.g. ./test.sh -a true -b false (default : true)"
echo "=============================================="
while getopts 'a:b:c:d:e:f:g:hi:j:k:' OPT;
do
    case $OPT in
	a)
	    set_primary="$OPTARG";;
	b)
	    set_secondary="$OPTARG";;
	c)
	    set_libnl="$OPTARG";;
	d)
	    run_mysql="$OPTARG";;
	e)
	    run_ssdb="$OPTARG";;
	f)
	    run_pgsql="$OPTARG";;
	g)
	    run_mongoose="$OPTARG";;
	h)
	    exit;; # -h is for help
	i)
	    run_mediatomb="$OPTARG";;
	j)
	    run_redis="$OPTARG";;
	k)
	    run_tomcat="$OPTARG";;
	?)
	    echo "Usage: `basename $0` [options]"
    esac
done
shift $(($OPTIND - 1))

echo "please make sure two machines have been started and election finished"

# some settings for libnl
# it is a must if you want to retrieve accurate test data
if [ "$set_libnl" = true ] ; then
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
fi

# some settings in secondary machine qemu monitor
if [ "$set_secondary" = true ] ; then
    ssh hkucs@$secondary_ip "\
    (\
    echo {\'execute\':\'qmp_capabilities\'};\
    echo {\'execute\': \'nbd-server-start\', \'arguments\': {\'addr\': {\'type\': \'inet\', \'data\': {\'host\': \'10.22.1.1\', \'port\': \'8889\'} } }};\
    echo {\'execute\': \'nbd-server-add\', \'arguments\': {\'device\': \'colo-disk0\', \'writable\': true } };\
    sleep 10;\
    ) | telnet localhost 4444"
fi

# some settings in primary machine qemu monitor
if [ "$set_primary" = true ] ; then
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
fi

########   MYSQL ############
if [ "$run_mysql" = true ] ; then
    printf "\n\n\n\n"
    echo "=============================================="
    echo "######## start mysql and run sysbench ########"
    echo "=============================================="
    printf "\n\n"
    # vm_ip = 10.22.1.150
    # start mysql server
    ssh cheng@$vm_ip "sudo killall -9 mysqld; screen -S mysql -d -m ./mysql/mysql-install/libexec/mysqld --defaults-file=./mysql/my.cnf"
    
    sleep 3
    # run-sysbench in client side
    requests=100 #default : 1 (number of requests)
    ssh hkucs@$client_ip "./run-sysbench -p 7006 -i $vm_ip -n $requests"
    
    sleep 3
fi

########    SSDB ############
if [ "$run_ssdb" = true ] ; then
    printf "\n\n\n\n"
    echo "=============================================="
    echo "########## start ssdb and run bench ##########"
    echo "=============================================="
    printf "\n\n"
    # vm_ip = 10.22.1.150
    # start ssdb server
    ssh cheng@$vm_ip "sudo killall -9 ssdb; screen -S ssdb -d -m ./ssdb/ssdb-master/ssdb-server ./ssdb/ssdb-master/ssdb.conf"
    
    sleep 3
    # run ssdb-bench in client side
    requests=10000 #default : 10000
    clients=50 #default : 50    
    ssh hkucs@$client_ip "./RDMA_Paxos/apps/ssdb/ssdb-master/tools/ssdb-bench $vm_ip 8888 $requests $clients"

    sleep 3
fi

########    pgsql ############
if [ "$run_pgsql" = true ] ; then
    printf "\n\n\n\n"
    echo "=============================================="
    echo "######### start pgsql and run bench ##########"
    echo "=============================================="
    printf "\n\n"
    # vm_ip = 10.22.1.150
    # start pgsql server
    ssh cheng@$vm_ip "sudo killall -9 postgres; ./pgsql/install/bin/pg_ctl stop -D ./pgsql/install/data; sleep 5; nohup ./pgsql/install/bin/pg_ctl start -D ./pgsql/install/data> pgsql.out 2> pgsql.err < /dev/null &"
    # see https://github.com/wangchenghku/COLO/blob/master/apps/pgsql/run
    # see also https://github.com/MichaelXSChen/vmft-eval/blob/master/ye_benchmark/cfgs/origin/pgsql.cfg
    # (todo)

    sleep 10
    # run pgsql bench in client side
    clients=1 #default : 20 (number of concurrent clients)
    threads=1 #default : 10 (number of threads)
    transactions=10 #default : 100 (number of transactions each client runs)
    ssh hkucs@$client_ip "./postgresql-9.3.5/contrib/pgbench/pgbench -i -h $vm_ip -p 7000 -U root dbtest; sleep 3; ./postgresql-9.3.5/contrib/pgbench/pgbench -h $vm_ip -p 7000  -U root dbtest -c $clients -j $threads -t $transactions"

    sleep 3
fi

########    mongoose ############
if [ "$run_mongoose" = true ] ; then
    printf "\n\n\n\n"
    echo "=============================================="
    echo "####### start mongoose and run bench #########"
    echo "=============================================="
    printf "\n\n"
    # vm_ip = 10.22.1.150
    # start mongoose server
    threads=2 #default : 2
    ssh cheng@$vm_ip "sudo killall -9 mg-server server.out; cd mongoose; rm .db -rf; screen -S mongoose -d -m ./mg-server -I /usr/bin/php-cgi -t $threads"
    # cd ~/mongoose-5.2/examples; ./server -listening_port 7777 -document_root /home/cheng/mongoose-5.2/examples/ -cgi_interpreter /usr/bin/php-cgi

    sleep 3
    # run mongoose bench in client side
    # see https://github.com/wangchenghku/COLO/blob/master/apps/mongoose/run
    # see also https://github.com/wangchenghku/COLO/blob/master/apps/mongoose/run-client
    # (not sure if it is right, todo)
    requests=128 #default : 128
    concurrency=8 #default : 8
    ssh hkucs@$client_ip "ab -n 128 -c 16 http://$vm_ip:8080/test.php"

    sleep 3
fi

########    mediatomb ############
if [ "$run_mediatomb" = true ] ; then
    printf "\n\n\n\n"
    echo "=============================================="
    echo "####### start mediatomb and run bench ########"
    echo "=============================================="
    printf "\n\n"
    # vm_ip = 10.22.1.150
    # start mediatomb server
    ssh cheng@$vm_ip "sudo killall -9 mediatomb; cd mediatomb; screen -S mediatomb -d -m ./install/bin/mediatomb -m /home/cheng/mediatomb/"
    # see https://github.com/wangchenghku/COLO/blob/master/apps/mediatomb/start-server
    # (some arguments may lost; todo)
    
    sleep 3
    # run mediatomb in client side
    requests=8 #default : 8
    concurrency=8 #default : 8
    ssh hkucs@$client_ip "ab -n $requests -c $concurrency http://$vm_ip:49152/content/media/object_id/5/res_id/none/pr_name/vlcmpeg/tr/1"

    sleep 3
fi

########    redis ############
if [ "$run_redis" = true ] ; then
    printf "\n\n\n\n"
    echo "=============================================="
    echo "######### start redis and run bench ##########"
    echo "=============================================="
    printf "\n\n"
    # vm_ip = 10.22.1.150
    # start redis server
    ssh cheng@$vm_ip "sudo killall -9 redis; screen -S redis -d -m ./redis/install/bin/redis-server"
    # nothing on github
    # see https://github.com/wangchenghku/RDMA-PAXOS/blob/master/apps/redis/run
    # (todo)

    sleep 3
    # run redis in client side
    requests=10000000 #default : 100000000
    clients=16 #default : 16
    pipeline=4000 #default : 4000 (pipeline numreqs)
    random=100000 #default : 100000 (Use random keys for SET/GET/INCR
    ssh hkucs@$client_ip "./RDMA_Paxos/apps/redis/install/redis-benchmark -h $vm_ip -p 6379 -n $requests -c $clients -t set -P $pipeline -r $random"

    sleep 3
fi


########    tomcat ############
if [ "$run_tomcat" = true ] ; then
    printf "\n\n\n\n"
    echo "=============================================="
    echo "######### start tomcat and run bench #########"
    echo "=============================================="
    printf "\n\n"
    # vm_ip = 10.22.1.150
    # start tomcat server
    ssh cheng@$vm_ip "sudo service tomcat7 restart;"

    sleep 3
    # run tomcat in client side
    requests=8 #default : 8
    concurrency=8 #default : u
    ssh hkucs@$client_ip "ab -n $requests -c $concurrency http://$vm_ip:8088/index.jsp"

    sleep 3
fi

echo "test done."
