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

main := dnsname @{ printf("HAPPY END!\n"); res = 1; };

}%%

%%write data;

#define TEST(name) parsename(name, strlen(name)+1)

int parsename(unsigned char *buf, int buflen) {
  int cs, res = 0;
  int seglen = 0;
  unsigned char uint8_acc[16];
  unsigned int acc8pos;
  unsigned char *p = (void *) buf;
  unsigned char *pe = p + buflen;
  unsigned char *eof = pe;
  long runlen;
  unsigned short uint16_acc;
  unsigned long uint32_acc;
  debug(DNS_PARSE,"Parsing reply, length: %d\n", buflen);
  %%write init;
  %%write exec;
  debug(DNS_PARSE,"parse result: %d, seglen: %d, pos: %d, c: 0x%02x\n",
          res, seglen, p-buf, *p);
  return res;
}

int main(int argc, char *argv[]) {
  assert(TEST("\003foo\006domain\003com\000"));
  assert(TEST("\022safebrowsing-cache\006google\003com"));
  exit(0);
}
