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

static int store_32(unsigned char **pp, unsigned char *pe, uint32_t val) {
  return (store_16(pp, pe, val >> 16) && store_16(pp, pe, val & 0xffff));
}

static int store_str(unsigned char **pp, unsigned char *pe, char *str) {
  unsigned char *pce = (void *)str;
  unsigned char *pc = (void *)str;
  int len;
  while(*pc && (*pp < pe)) {
    /* find the length of the next name segment */
    for(len=0, pce=pc; ((len < 64) && (*pce) && (*pce != '.')); pce++, len++) {
      ;
    }
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

int ydns_encode_rr_start(unsigned char **buf, int buf_sz,
		char *name,
		uint16_t type,
		uint16_t class,
		uint32_t ttl) {
  unsigned char *p = *buf;
  unsigned char *pe = p + buf_sz;
  int result = 1;

  result = result && store_str(&p, pe, name);
  result = result && store_16(&p, pe, type);
  result = result && store_16(&p, pe, class);
  result = result && store_32(&p, pe, ttl);
  if (result) {
    *buf = p;
  }
  return result;
}

int ydns_encode_rr_data(unsigned char **buf, int buf_sz, 
			void *src, int len) {
  unsigned char *p = *buf;
  unsigned char *pe = p + buf_sz;
  int result = 1;
  result = result && store_16(&p, pe, len);
  if (len <= pe - p) {
    memcpy(p, src, len);
    p += len; 
  } else {
    result = 0;
  }

  if (result) {
    *buf = p;
  }
  return result;
}

int ydns_encode_rr_soa(unsigned char **buf, int buf_sz,
			char *nsname,
			char *admin,
			uint32_t serial,
			uint32_t refresh,
			uint32_t retry,
			uint32_t expire,
			uint32_t min_ttl) {
  unsigned char *p = *buf;
  unsigned char *ps = *buf;
  unsigned char *pe = p + buf_sz;
  int result = 1;

  result = result && store_16(&p, pe, 0); /* length, to re-store later */
  result = result && store_str(&p, pe, nsname);
  result = result && store_str(&p, pe, admin);
  result = result && store_32(&p, pe, serial);
  result = result && store_32(&p, pe, refresh);
  result = result && store_32(&p, pe, retry);
  result = result && store_32(&p, pe, expire);
  result = result && store_32(&p, pe, min_ttl);

  result = result && store_16(&ps, pe, (p - *buf - 2)); /* length, now calculated */

  if (result) {
    *buf = p;
  }
  return result;
}

int ydns_encode_pdu(unsigned char **buf, int buf_sz, 
		uint16_t qtype,
		char *name,
		uint16_t id,
		uint16_t opcode_flags, 
		uint16_t qdcount,
		uint16_t ancount,
		uint16_t nscount,
		uint16_t arcount,
		uint16_t qclass) {
  unsigned char *p = *buf;
  unsigned char *pe = p + buf_sz;
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

  return ydns_encode_pdu(buf, buf_sz, qtype, name, id, opcode_flags, qdcount, ancount, nscount, arcount, qclass);
}

