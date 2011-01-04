#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "dns.h"

%%{

machine dns;

include "dnsname.rl";

main := dnsname %/{ printf("HAPPY EOF\n"); res = 1; } 
                @{ printf("HAPPY END!\n"); res = 1; };

}%%

%%write data;

#define TEST(name) parsename(name, strlen(name)+1, 0)
#define TEST2(ofs, len, name) parsename(name, len, ofs)

int parsename(unsigned char *buf, int buflen, int startpos) {
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
  acchpos = 0;
  memset(hostname_acc, 0, sizeof(hostname_acc));
  debug(DNS_PARSE,"Parsing reply, length: %d, startpos: %d\n", buflen, startpos);
  %%write init;
  p += startpos; 
  %%write exec;
  debug(DNS_PARSE,"parse result: %d, seglen: %d, pos: %d, c: 0x%02x\n",
          res, seglen, p-buf, *p);
  if (res == 1 ) {
    printf("====> Decoded hostname: '%s'\n", hostname_acc);
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
  printf("================== All simple tests passed.==============\n");
#define S "\003x01\006domain\003com\000\x01X\x02YY\300\000"
  assert(TEST2(21, 23, S));
#define S "\003x01\006domain\003com\000\x01X\x02YY\001A\300\000"
  assert(TEST2(21, 25, S));
#define S "\003x01\006domain\003com\000\x01X\x02YY\001A\300\000\001B\300\025+\000"
  assert(TEST2(25, 29, S));
#define S "\003x01\006domain\003com\000\x01X\x02YY\001A\300\000\001B\300\025\001C\300\031"
  assert(TEST2(29, 33, S));
  printf("=========================\n");
  exit(0);
}
