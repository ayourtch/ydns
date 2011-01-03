all: test-label-run test-dnsname-run dnstest

dnstest: reply.c main.c
	gcc -g -Werror -Wall -o dnstest reply.c main.c
clean:
	rm -f *.o dnstest reply.c 
	rm -f test-dnsname.c test-dnsname test-label test-label.c

reply.c: reply.rl  
	ragel -e reply.rl

view-label:
	ragel -e -p -V view-label.rl | dotty -

test-dnsname-run: test-dnsname.rl dnsname.rl
	ragel test-dnsname.rl
	gcc -o test-dnsname test-dnsname.c
	./test-dnsname

test-label-run: test-label.rl dnsname.rl
	ragel test-label.rl
	gcc -o test-label test-label.c
	./test-label

