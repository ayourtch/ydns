all: test-label-run test-dnsname-run dnstest dnsstest

dnstest: decode-pdu.c build-pdu.c dnstest.c dns.h
	gcc -g -Werror -Wall -Wno-unused -o dnstest decode-pdu.c build-pdu.c dnstest.c

dnsstest: dnsstest.c build-pdu.c decode-pdu.c dns.h
	gcc -g -Werror -Wall -Wno-unused -o dnsstest dnsstest.c decode-pdu.c build-pdu.c

ydns.so: decode-pdu.c build-pdu.c ydns.c dns.h
	gcc -g -I/usr/include/lua5.1 -fPIC -Wall -shared -o ydns.so decode-pdu.c build-pdu.c ydns.c
clean:
	rm -f *.o dnstest dnsstest decode-pdu.c *.so
	rm -rf *.dSYM
	rm -f test-dnsname.c test-dnsname test-label test-label.c

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

