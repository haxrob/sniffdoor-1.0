# Makefile for sniffserver	by wzt

CC 	= gcc
CFLAGS 	= -w -O2 -I../include

.c.o:
	$(CC) $(CFLAGS) \
	-c -o $*.o $<

OBJS = sniffdoor.o socket.o
	
sniffdoor: $(OBJS)
	$(CC) -o sniffdoor $(OBJS)

clean:
	rm -f sniffdoor *.o