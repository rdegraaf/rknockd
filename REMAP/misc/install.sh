#!/bin/sh

BUILD_DIR=/home/degraaf/remap
MODULE_DIR=/lib/modules/2.6.16.16-bs2-um/kernel

# Pre-install
iptables -F 2>/dev/null
iptables -F -t nat 2>/dev/null
iptables -X 2>/dev/null
rmmod ipt_REMAP xt_tcpudp xt_state xt_conntrack iptable_nat ip_nat \
    ip_conntrack nfnetlink iptable_filter ip_tables \
    ipt_LOG ipt_ttl x_tables 2>/dev/null

modcount=`cat /proc/modules | wc -l`
if [ $modcount -ne 0 ]
then
    echo "Error: some modules were not successfully unloaded"
    exit
fi

# install kernel modules
cp $BUILD_DIR/xt_conntrack.ko $MODULE_DIR/net/netfilter/
cp $BUILD_DIR/ipt_REMAP.ko $MODULE_DIR/net/ipv4/netfilter/
cp $BUILD_DIR/System.map /lib/modules/2.6.16.16-bs2-um/

# install kernel headers
cp $BUILD_DIR/ipt_REMAP.h /usr/include/linux/netfilter_ipv4/ipt_REMAP.h

# install iptables
cp $BUILD_DIR/iptables.8 /usr/man/man8/
cp $BUILD_DIR/libipt_REMAP.so /usr/lib/iptables/

# Post-install
depmod
modprobe ipt_REMAP

