CC=gcc
CXX=g++
RM=rm -f

CCFLAGS=-Wall -Wextra -std=c99 -pedantic -g -O2 -DDEBUG
CXXFLAGS=-Wall -Wextra -ansi -pedantic  -g -O2 -DDEBUG

spaclient_OBJS=spaclient.o
spaclient_CCFLAGS=
spaclient_LDFLAGS=
spaclient_LIBS=-lcrypto

spaserver_OBJS=spamain.o Config.o SpaConfig.o NFQ.o Listener.o \
	       SignalTranslator.o
spaserver_CXXFLAGS=-IREMAP/linux-2.6.20.7/include \
		`libgcrypt-config --cflags` \
		`pkg-config --cflags libxml++-2.6`
spaserver_LDFLAGS=-L/usr/local/lib
spaserver_LIBS=`libgcrypt-config --libs` `pkg-config --libs libxml++-2.6` \
		-lnetfilter_queue

.PHONY: all clean distclean depend

all: spaclient spaserver

spaclient: ${spaclient_OBJS}
	${CC} -o $@ $^ ${LDFLAGS} ${spaclient_LDFLAGS} ${spaclient_LIBS}

spaserver: ${spaserver_OBJS}
	${CXX} -o $@ $^ ${LDFLAGS} ${spaserver_LDFLAGS} ${spaserver_LIBS}

%.o: %.c
	${CC} -c ${CCFLAGS} ${spaclient_CCFLAGS} $<

%.o: %.cpp
	${CXX} -c ${CXXFLAGS} ${spaserver_CXXFLAGS} $<

clean:
	${RM} a.out *.o *~

distclean: clean
	${RM} spaclient spaserver .depend

depend:
	${CC} -MM *.c *.cpp >.depend

# dependencies
-include .depend

