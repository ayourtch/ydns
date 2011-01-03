all: dnstest

dnstest: reply.c main.c
	gcc -g -o dnstest reply.c main.c
clean:
	rm -f *.o label.rl dnstest reply.c

reply.c: reply.rl label.rl 
	ragel -e reply.rl
label.rl: gen-label.lua
	lua gen-label.lua >$@
