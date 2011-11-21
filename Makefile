RM=rm
DBG=-g
CC=gcc
SOURCES=config.c iptables.c users.c sockets.c modules.c runner.c manager.h
BINARY=manager
LIBS=-lcrypt
OUTDIR=bindir

all:	binary
	cd modules; make

binary:
	mkdir -p $(OUTDIR)
	$(CC) $(DBG) -o $(OUTDIR)/$(BINARY) $(SOURCES) -ldl -rdynamic $(LIBS)

clean:
	$(RM) -rf $(BINARY)
