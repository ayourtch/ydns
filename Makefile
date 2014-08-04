all: dnstest dnsstest

dnstest: decode-pdu.c build-pdu.c dnstest.c dns.h
	gcc -g -Werror -Wall -Wno-unused -o dnstest decode-pdu.c build-pdu.c dnstest.c

dnsstest: dnsstest.c build-pdu.c decode-pdu.c dns.h
	gcc -g -Werror -Wall -Wno-unused -o dnsstest dnsstest.c decode-pdu.c build-pdu.c

ydns.so: decode-pdu.c build-pdu.c ydns.c dns.h
	gcc -g -I/usr/include/lua5.1 -fPIC -Wall -shared -o ydns.so decode-pdu.c build-pdu.c ydns.c
clean:
	rm -f *.o dnstest dnsstest *.so
	rm -rf *.dSYM

