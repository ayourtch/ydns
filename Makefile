all: test-label-run test-dnsname-run dnstest dnsstest

dnstest: reply.c build-pdu.c dnstest.c dns.h
	gcc -g -Werror -Wall -Wno-unused -o dnstest reply.c build-pdu.c dnstest.c

dnsstest: dnsstest.c reply.c dns.h
	gcc -g -Werror -Wall -Wno-unused -o dnsstest dnsstest.c reply.c 

ydns.so: reply.c request.c ydns.c dns.h
	gcc -g -I/usr/include/lua5.1 -fPIC -Wall -shared -o ydns.so reply.c request.c ydns.c
clean:
	rm -f *.o dnstest dnsstest reply.c *.so
	rm -rf *.dSYM
	rm -f test-dnsname.c test-dnsname test-label test-label.c

reply.c: reply.rl dnsname.rl
	ragel -e reply.rl

view-label:
	ragel -e -p -V view-label.rl | dotty -

test-dnsname-run: test-dnsname.rl dnsname.rl
	ragel test-dnsname.rl
	gcc -g -o test-dnsname test-dnsname.c
	./test-dnsname

test-label-run: test-label.rl dnsname.rl
	ragel test-label.rl
	gcc -o test-label test-label.c
	./test-label

