all: dnstest

dnstest: reply.c main.c
	gcc -g -o dnstest reply.c main.c
clean:
	rm -f *.o dnstest reply.c

reply.c: reply.rl  
	ragel -e reply.rl
