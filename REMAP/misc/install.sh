#!/bin/sh

BUILD_DIR=/home/degraaf/remap

# Pre-install
iptables -F 2>/dev/null
iptables -X 2>/dev/null
rmmod xt_tcpudp xt_state ip_conntrack nfnetlink iptable_filter ip_tables \
    ipt_REMAP ipt_LOG ipt_ttl x_tables nfnetlink 2>/dev/null

modcount=`cat /proc/modules | wc -l`
if [ $modcount -ne 0 ]
then
    echo "Error: some modules were not successfully unloaded"
    exit
fi

# install kernel modules
cp $BUILD_DIR/ipt_REMAP.ko /lib/modules/2.6.16.16-bs2-um/kernel/net/ipv4/netfilter/
cp $BUILD_DIR/System.map /lib/modules/2.6.16.16-bs2-um/

# install kernel headers
cp $BUILD_DIR/ipt_REMAP.h /usr/include/linux/netfilter_ipv4/ipt_REMAP.h

# install iptables
cp $BUILD_DIR/iptables.8 /usr/man/man8/
cp $BUILD_DIR/libipt_REMAP.so /usr/lib/iptables/

# Post-install
depmod
modprobe ipt_REMAP

