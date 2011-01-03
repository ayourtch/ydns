#include <stdio.h>
#include <string.h>
#include <assert.h>

#define DEBUG
#ifdef DEBUG 
#define debug(what, ...) printf(__VA_ARGS__)
#else
#define debug(what, ...)
#endif



%%{

machine dns;

include "dnsname.rl";

main := label* 0 @{ printf("LABEL HAPPY END!\n"); res = 1; };

}%%

%%write data;

#define TEST(name) parsename(name, strlen(name)+1)

int parsename(unsigned char *buf, int buflen) {
  int cs, res = 0;
  int seglen = 0;
  unsigned char uint8_acc[16];
  unsigned int acc8pos;
  unsigned char *p = (void *) buf;
  unsigned char *sav_p;
  unsigned char *pe = p + buflen;
  unsigned char *eof = pe;
  /* runlen gets reset to -1 at the start of domainname, 
     which we do not do here */
  int runlen = -1;
  unsigned short uint16_acc;
  unsigned long uint32_acc;
  int top;
  int stack[10];
  debug(DNS_PARSE,"Parsing reply, length: %d\n", buflen);
  %%write init;
  %%write exec;
  debug(DNS_PARSE,"parse result: %d, seglen: %d, pos: %d, c: 0x%02x\n",
          res, seglen, p-buf, *p);
  return res;
}

int main(int argc, char *argv[]) {
  assert(TEST("\003foo"));
  assert(TEST("\003f01"));
  assert(TEST("\003f-1"));
  assert(!TEST("\003f_1"));
  assert(TEST("\022safebrowsing-cache"));
  assert(TEST("\022safebrowsing-cache"));
  assert(!TEST("\022safebrowsingcache-"));
  assert(!TEST("\0225afebrowsingcache-"));
  assert(!TEST("\0225afebrowingcache-"));
  printf("All tests passed.\n");
  exit(0);
}
