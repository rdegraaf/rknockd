#!/bin/sh

KERNEL_SRC=/home/degraaf/firewall/trunk/src/rknock/REMAP/linux-2.6.16.16
KERNEL_BUILD=/home/degraaf/build/linux-2.6.16.16
KERNEL_FILES=".config \
              include/linux/netfilter_ipv4/ipt_REMAP.h \
              net/netfilter/xt_conntrack.c \
              net/ipv4/netfilter/Kconfig \
              net/ipv4/netfilter/Makefile \
              net/ipv4/netfilter/ipt_REMAP.c"
KERNEL_TARGETS="System.map \
                include/linux/netfilter_ipv4/ipt_REMAP.h \
                net/netfilter/xt_conntrack.ko \
                net/ipv4/netfilter/ipt_REMAP.ko"
KERNEL_BIN="/home/degraaf/bin/linux"

IPTABLES_SRC=/home/degraaf/firewall/trunk/src/rknock/REMAP/iptables-1.3.5
IPTABLES_BUILD=/home/degraaf/build/iptables-1.3.5
IPTABLES_FILES="extensions/libipt_REMAP.man \
                extensions/libipt_REMAP.c \
                extensions/Makefile"
IPTABLES_TARGETS="extensions/libipt_REMAP.so iptables.8"

INSTALL_HOST=eregion

copy_iptables()
{
    for f in $IPTABLES_FILES
    do
        diff -N $IPTABLES_BUILD/$f $IPTABLES_SRC/$f >/dev/null
        if [ $? -eq 1 ]
        then
            echo "Copying $f..."
            cp $IPTABLES_SRC/$f $IPTABLES_BUILD/$f
        fi
    done
}

copy_kernel()
{
    for f in $KERNEL_FILES
    do
        diff -N $KERNEL_BUILD/$f $KERNEL_SRC/$f >/dev/null
        if [ $? -eq 1 ]
        then
            echo "Copying $f..."
            cp $KERNEL_SRC/$f $KERNEL_BUILD/$f
        fi
    done
}

build_kernel()
{
    olddir=`pwd` && cd $KERNEL_BUILD && make ARCH=um && cd $olddir
}

build_iptables()
{
    olddir=`pwd` && cd $IPTABLES_BUILD && make PREFIX=/usr KERNEL_DIR=$KERNEL_BUILD && cd $olddir
}

build_libnetfilter_mqueue()
{
    olddir=`pwd` && cd $LIBNETFILTER_BUILD && make && cd $old
}

install_iptables()
{
    ping -c 1 -q $INSTALL_HOST >/dev/null
    if [ $? != 0 ]
    then
        return 1
    fi

    targets=""
    for t in $IPTABLES_TARGETS
    do
        targets="$targets $IPTABLES_BUILD/$t "
    done
    
    scp $targets degraaf@$INSTALL_HOST:remap
}

install_kernel()
{
    targets=""
    for t in $KERNEL_TARGETS
    do
        targets="$targets $KERNEL_BUILD/$t "
    done
    scp $targets degraaf@$INSTALL_HOST:remap
}

install_misc()
{
    targets="misc/install.sh misc/iptables.save"
    scp $targets degraaf@$INSTALL_HOST:remap
}

case "$1" in
    iptables)
        copy_iptables && build_iptables
        retval=$?
        ;;
        
    kernel)
        copy_kernel && build_kernel
        retval=$?
        ;;
    
    install)
        install_kernel && install_iptables && install_misc 
        retval=$?
        ;;
    
    all)
        copy_kernel && copy_iptables && build_kernel && build_iptables
        retval=$?
        ;;
    *)
        echo "Usage: $0 {iptables|kernel|install|all}"
        retval=1
        ;;
esac
exit $retval
