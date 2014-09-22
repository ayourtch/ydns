all: dnstest dnsstest sqlite3dns fuzz-parse

dnstest: decode-pdu.c build-pdu.c dnstest.c dns.h
	gcc -g -Werror -Wall -Wno-unused -o dnstest decode-pdu.c build-pdu.c dnstest.c

dnsstest: dnsstest.c build-pdu.c decode-pdu.c dns.h
	gcc -g -Werror -Wall -Wno-unused -o dnsstest dnsstest.c decode-pdu.c build-pdu.c
sqlite3dns: sqlite3dns.c build-pdu.c decode-pdu.c dns.h
	gcc -g -Werror -Wall -Wno-unused -o sqlite3dns sqlite3dns.c decode-pdu.c build-pdu.c -lsqlite3
	sudo setcap CAP_NET_BIND_SERVICE=+ep sqlite3dns

fuzz-parse: fuzz-parse.c build-pdu.c decode-pdu.c dns.h
	gcc -g -Werror -Wall -Wno-unused -o fuzz-parse fuzz-parse.c build-pdu.c decode-pdu.c

ydns.so: decode-pdu.c build-pdu.c ydns.c dns.h
	gcc -g -I/usr/include/lua5.1 -fPIC -Wall -shared -o ydns.so decode-pdu.c build-pdu.c ydns.c
clean:
	rm -f *.o dnstest dnsstest sqlite3dns fuzz-parse *.so
	rm -rf *.dSYM

