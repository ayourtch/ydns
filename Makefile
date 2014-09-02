all: dnstest dnsstest sqlite3dns

dnstest: decode-pdu.c build-pdu.c dnstest.c dns.h
	gcc -g -Werror -Wall -Wno-unused -o dnstest decode-pdu.c build-pdu.c dnstest.c

dnsstest: dnsstest.c build-pdu.c decode-pdu.c dns.h
	gcc -g -Werror -Wall -Wno-unused -o dnsstest dnsstest.c decode-pdu.c build-pdu.c
sqlite3dns: sqlite3dns.c build-pdu.c decode-pdu.c dns.h
	gcc -g -Werror -Wall -Wno-unused -o sqlite3dns sqlite3dns.c decode-pdu.c build-pdu.c -lsqlite3

ydns.so: decode-pdu.c build-pdu.c ydns.c dns.h
	gcc -g -I/usr/include/lua5.1 -fPIC -Wall -shared -o ydns.so decode-pdu.c build-pdu.c ydns.c
clean:
	rm -f *.o dnstest dnsstest sqlite3dns *.so
	rm -rf *.dSYM

