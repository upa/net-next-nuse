#!/bin/bash -e

IFNAME=`ip route |grep default | awk '{print $5}'`
GW=`ip route |grep default | awk '{print $3}'`
#XXX
IPADDR=`echo $GW | sed -r "s/([0-9]+\.[0-9]+\.[0-9]+\.)([0-9]+)$/\1\`expr \2 + 10\`/"`

# ip route
# ip address
# ip link

NUSE_CONF=/tmp/nuse.conf

cat > ${NUSE_CONF} << ENDCONF

interface ${IFNAME}
	address ${IPADDR}
	netmask 255.255.255.0
	macaddr 00:01:01:01:01:02
	viftype RAW

route
	network 0.0.0.0
	netmask 0.0.0.0
	gateway ${GW}

ENDCONF

sudo NUSECONF=${NUSE_CONF} ./nuse ping 127.0.0.1 -c 2

if [ "$1" == "--extended" ] ; then
sudo NUSECONF=${NUSE_CONF} ./nuse ping ${GW} -c 2
sudo NUSECONF=${NUSE_CONF} ./nuse iperf -c ${GW} -p 2000 -t 3
sudo NUSECONF=${NUSE_CONF} ./nuse iperf -c ${GW} -p 8 -u -t 3
sudo NUSECONF=${NUSE_CONF} ./nuse dig www.google.com
sudo NUSECONF=${NUSE_CONF} ./nuse host www.google.com
sudo NUSECONF=${NUSE_CONF} ./nuse nslookup www.google.com 
#sudo NUSECONF=${NUSE_CONF} ./nuse nc www.google.com 80
sudo NUSECONF=${NUSE_CONF} ./nuse wget www.google.com -O -
fi
