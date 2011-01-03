all: test-dnsname-run dnstest

dnstest: reply.c main.c
	gcc -g -Werror -Wall -o dnstest reply.c main.c
clean:
	rm -f *.o dnstest reply.c test-dnsname.c test-dnsname

reply.c: reply.rl  
	ragel -e reply.rl

view-label:
	ragel -V view-label.rl | dotty -

test-dnsname.c: test-dnsname.rl dnsname.rl
	ragel test-dnsname.rl

test-dnsname-run: test-dnsname.c
	gcc -o test-dnsname test-dnsname.c
	./test-dnsname


