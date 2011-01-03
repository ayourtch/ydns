#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "dns.h"

%%{

machine dns;

include "dnsname.rl";

main := dnsname @{ printf("HAPPY END!\n"); res = 1; };

}%%

%%write data;

#define TEST(name) parsename(name, strlen(name)+1)

int parsename(unsigned char *buf, int buflen) {
  int cs, res = 0;
  int seglen = 0;
  unsigned char uint8_acc[16];
  unsigned int acc8pos;
  unsigned char hostname_acc[HOSTNAME_SZ];
  unsigned int acchpos;
  unsigned char *p = (void *) buf;
  unsigned char *sav_p; 
  unsigned char *pe = p + buflen;
  unsigned char *eof = pe;
  int runlen = 0xdead; // corrupt deliberately
  unsigned short uint16_acc;
  unsigned long uint32_acc;
  int top;
  int stack[10];
  debug(DNS_PARSE,"Parsing reply, length: %d\n", buflen);
  %%write init;
  %%write exec;
  debug(DNS_PARSE,"parse result: %d, seglen: %d, pos: %d, c: 0x%02x\n",
          res, seglen, p-buf, *p);
  if (res == 1 ) {
    printf("Decoded hostname: '%s'\n", hostname_acc);
  }
  return res;
}

int main(int argc, char *argv[]) {
  assert(TEST("\003foo\006domain\003com\000"));
  assert(TEST("\003f01\006domain\003com\000"));
  assert(TEST("\003f-1\006domain\003com\000"));
  assert(!TEST("\003f_1\006domain\003com\000"));
  assert(TEST("\022safebrowsing-cache\006google\003com"));
  assert(TEST("\022safebrowsing-cache\006google\003com\0xc000"));
  assert(!TEST("\022safebrowsingcache-\006google\003com"));
  assert(!TEST("\0225afebrowsingcache-\006google\003com"));
  assert(!TEST("\0225afebrowingcache-\006google\003com"));
  printf("All tests passed.\n");
  exit(0);
}
