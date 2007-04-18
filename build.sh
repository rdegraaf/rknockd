#!/bin/sh

TARGETS="spaserver spaconfig.xml"

INSTALL_HOST=nevrast

install_targets()
{
    scp $TARGETS degraaf@$INSTALL_HOST:
}

case "$1" in
    client)
        make spaclient
        retval=$?
        ;;
    server)
        make spaserver
        retval=$?
        ;;
    install)
        install_targets
        retval=$?
        ;;
    *)
        echo "Usage: $0 {client|server|all|install}"
        retval=1
        ;;
esac
exit $retval
