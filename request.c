#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "dns.h"


static int store_8(unsigned char **pp, unsigned char *pe, uint8_t val) {
  if(*pp == pe) {
    return 0;
  } else {
    *(*pp)++ = val;
    return 1;
  }
}
static int store_16(unsigned char **pp, unsigned char *pe, uint16_t val) {
  return (store_8(pp, pe, val >> 8) && store_8(pp, pe, val & 0xff));
}

static int store_str(unsigned char **pp, unsigned char *pe, char *str) {
  unsigned char *pce = (void *)str;
  unsigned char *pc = (void *)str;
  int len;
  while(*pc && (*pp < pe)) {
    /* find the length of the next name segment */
    for(len=0, pce=pc; ((len < 64) && (*pce) && (*pce != '.')); pce++, len++);
    debug(STORE_STR, "Seg len: %ld (len: %d)\n", pce-pc, len);
    if(len > 63) { return 0; }
    /* try to store this name segment to target buffer */
    if(store_8(pp, pe, (uint8_t) len)) {
      while(pce != pc) {
        // debug(STORE_STR, "storing '%c'\n", *pc);
        if(!store_8(pp, pe, *pc++)) { return 0; };
      }
    }
    /* if it was a dot, skip it */
    if(*pc == '.') { pc++; }
  }
  if(len > 0) {
    return store_8(pp, pe, 0);
  } else {
    return 1;
  }
}

int ydns_encode_request(unsigned char **buf, int buf_sz, int type, char *name, uint16_t id) {
  unsigned char *p = *buf;
  unsigned char *pe = p + buf_sz;
  /* +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+ 
      0   0  0  0  0  0  0  1  0  0 0  0  0  0  0  0   */
  uint16_t opcode_flags = 0x0100;
  uint16_t qdcount = 1;
  uint16_t ancount = 0;
  uint16_t nscount = 0;
  uint16_t arcount = 0;
  uint16_t qtype = type;
  uint16_t qclass = 1;
  
  int result = 1;

  debug("Encoding start, p:%p, pe: %p\n", (void *)p, (void *)pe);

  result = result && store_16(&p, pe, id);
  result = result && store_16(&p, pe, opcode_flags);
  result = result && store_16(&p, pe, qdcount);
  result = result && store_16(&p, pe, ancount);
  result = result && store_16(&p, pe, nscount);
  result = result && store_16(&p, pe, arcount);
  result = result && store_str(&p, pe, name);
  result = result && store_16(&p, pe, qtype);
  result = result && store_16(&p, pe, qclass);
  if (result) {
    *buf = p;
  }
  return result;
}

