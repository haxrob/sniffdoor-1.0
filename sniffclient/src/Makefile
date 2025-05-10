# Makefile for sniffclient	by wzt

CC 	= gcc
CFLAGS 	= -w -O2 -I../include

.c.o:
	$(CC) $(CFLAGS) \
	-c -o $*.o $<

OBJS = client.o socket.o
	
sniffclient: $(OBJS)
	$(CC) -o sniffclient $(OBJS)

clean:
	rm -f sniffclient *.o