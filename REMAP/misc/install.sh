#!/bin/sh

BUILD_DIR=/home/degraaf/remap
MODULE_DIR=/lib/modules/2.6.20.7-skas3-v9-pre9-um

# Pre-install
iptables -F 2>/dev/null
iptables -F -t nat 2>/dev/null
iptables -X 2>/dev/null
rmmod ipt_REMAP iptable_nat nf_conntrack_ipv4 xt_conntrack iptable_filter \
    ip_tables x_tables nf_nat 2>/dev/null

modcount=`cat /proc/modules | wc -l`
if [ $modcount -ne 0 ]
then
    echo "Error: some modules were not successfully unloaded"
    exit
fi

# install kernel modules
cp $BUILD_DIR/ipt_REMAP.ko $MODULE_DIR/kernel/net/ipv4/netfilter/
cp $BUILD_DIR/System.map $MODULE_DIR

# install kernel headers
cp $BUILD_DIR/ipt_REMAP.h /usr/include/linux/netfilter_ipv4/ipt_REMAP.h

# install iptables
cp $BUILD_DIR/iptables.8 /usr/share/man/man8/
cp $BUILD_DIR/libipt_REMAP.so /usr/local/lib/iptables/

# Post-install
depmod
modprobe ipt_REMAP

# create test files
#echo -en "\x0a\x00\x01\x01\x0a\x00\x01\x02\x00\x00\x00\x00\xde\xad\x00\x16\x06\x00\x27\x10" >~degraaf/remap/testcmd
