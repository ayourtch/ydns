#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <assert.h>
#include "dns.h"

enum {
  ERR_OK = 0,
  ERR_OVERRUN,
  ERR_RDATA_BIG,
  ERR_DOMAIN_END,
  ERR_MALFORMED_NAME,
  ERR_RESERVED_LABEL_LEN,
  ERR_WILD_LABEL_POINTER
};

typedef struct parse_state {
  char *pb;
  char *p;
  char *pe;
  int err;
} parse_state_t;

typedef struct domain_parse_state {
  char *pb;
  char *p;
  char *pe;
  int err;
} domain_parse_state_t;

typedef void (*char_store_cb_t)(char c);

char decode_char(parse_state_t *ps) {
  return 0;
}

int decode_label(parse_state_t *ps, void *arg, char_store_cb_t cb) {
  char len;
  char c;
  for(len = decode_char(ps); (!ps->err) && (len > 0); len--) {
    c = decode_char(ps);
    if(ps->err) {
      return 0;
    } else {
      cb(c);
    }
  }
  return(ps->err);
}

int decode_domain(parse_state_t *ps, char **pp, int dmaxsz, int *dsz, char *domain) {
  int n = 10;
  char *sp = NULL;
  char *pd = domain;
  domain_parse_state_t domain_ps, *dps = &domain_ps;

  dps->pb = ps->pb;
  dps->p = *pp;
  dps->pe = ps->pe;
  dps->err = 0;

  *dsz = 0;
  assert(!ps->err);

  while (!dps->err) {
    assert(&domain_ps == dps);
    switch((((uint8_t)*dps->p) & 0xc0)) {

    case 0xc0:
      if (--n > 0) {
        int offs_hi = (0x3f & (uint8_t)*dps->p++);
        int offs = offs_hi * 256 + (uint8_t)*dps->p++;
        assert(offs >= 0);
        if (offs >= (ps->p - ps->pb)) {
          ps->err = ERR_WILD_LABEL_POINTER;
          return ps->err;
        }
        debugx(0, "jump: %d\n", offs);
        if(!sp) {
          sp = dps->p;
        }
        dps->p = dps->pb + offs;
      } else {
        ps->err = ERR_MALFORMED_NAME;
        return ps->err;
      }
      break;
    case 0x00:
      if (*dps->p) {
        debugx(0, "label: %d\n", *dps->p);
        assert(dsz >= 0);
        if (*dsz + 1 + ((uint8_t)*dps->p) < dmaxsz) {
          memcpy(pd, 1 + dps->p, (uint8_t)*dps->p);
          dmaxsz -= (uint8_t)*dps->p;
          pd += (uint8_t)*dps->p;
          *pd++ = '.';
          *pd = 0;
        } else {
        }
        dps->p += 1 + *dps->p;
      } else {
        dps->err = ERR_DOMAIN_END;
        dps->p++;
      }
      break;
    case 0x80:
    case 0x40: 
      ps->err = ERR_RESERVED_LABEL_LEN;
      return ps->err;
      break;
    }
  }
  if(ERR_DOMAIN_END == dps->err) {
    *pp = sp ? sp : dps->p;
  } else {
    ps->err = dps->err;
  }
  return ps->err;
}

int decode_u16(parse_state_t *ps, uint16_t *val) {
  assert(!ps->err);
  if (ps->p + 2 > ps->pe) {
    ps->p = ps->pe;
    ps->err = ERR_OVERRUN;
  }
  if (ps->err) {
    return ps->err;
  }
  *val = ntohs(*(uint16_t *)(ps->p));
  ps->p += 2;
  return ps->err;
}

int decode_u32(parse_state_t *ps, uint32_t *val) {
  assert(!ps->err);
  if (ps->p + 4 > ps->pe) {
    ps->p = ps->pe;
    ps->err = ERR_OVERRUN;
  }
  if (ps->err) {
    return ps->err;
  }
  *val = ntohl(*(uint32_t *)(ps->p));
  ps->p += 4;
  return ps->err;
}

int get_bytestring(parse_state_t *ps, uint16_t rdlength_in, uint16_t rdlength, char *rdata) {
  assert(!ps->err);
  if(rdlength_in < rdlength) {
    if(ps->p + rdlength <= ps->pe) {
      ps->p += rdlength;
    }
    ps->err = ERR_RDATA_BIG;
    return ps->err;
  }
  if(ps->p + rdlength > ps->pe) {
    ps->p = ps->pe;
    ps->err = ERR_OVERRUN;
    return ps->err;
  }
  memcpy(rdata, ps->p, rdlength);
  ps->p += rdlength;
  return ps->err;
}

int decode_rr(parse_state_t *ps, char *name, uint16_t *type,
              uint16_t *class, uint32_t *ttl, uint16_t *rdlength) {
  int namelen;

  if(decode_domain(ps, &ps->p, 255, &namelen, name)) {
    return ps->err;
  }
  if(decode_u16(ps, type)) {
    return ps->err;
  }
  if(decode_u16(ps, class)) {
    return ps->err;
  }
  if(decode_u32(ps, ttl)) {
    return ps->err;
  }
  if(decode_u16(ps, rdlength)) {
    return ps->err;
  }
  return ps->err;
}


int decode_question(parse_state_t *ps, char *qname, uint16_t *qtype, uint16_t *qclass) {
  int qnamelen;
  assert(!ps->err);
  assert(*(ps->p)+1 || 1);
  if(decode_domain(ps, &ps->p, 255, &qnamelen, qname)) {
    return ps->err;
  }
  if(decode_u16(ps, qtype)) {
    return ps->err;
  }
  if(decode_u16(ps, qclass)) {
    return ps->err;
  }
  return ps->err;
}

typedef enum {
  P_ID = 0, P_FLAGS, P_QDCOUNT, P_ANCOUNT, P_NSCOUNT, P_ARCOUNT, P_TOTALFIELDS
} packet_header_field_t;


int ydns_decode_packet(unsigned char *buf, int buflen, void *arg, decode_callbacks_t *cb) {
  parse_state_t pstate, *ps = &pstate;
  char namebuf[256];
  char namebuf2[256];
  int namelen2;
  uint16_t type = 0, class = 0, rdlength = 0;
  uint32_t ttl;
  char rdata[1024], *prdata = rdata;

  uint16_t ph[P_TOTALFIELDS];
  int i, j;

  ps->err = 0;
  ps->pb = ps->p = (void *)buf;
  ps->pe = ps->p + buflen;

  for(i=0; i<P_TOTALFIELDS; i++) {
    assert(&pstate == ps);
    if (decode_u16(ps, &ph[i])) {
      return ps->err;
    }
  }
  debug(0, "PDU decode ID: %04x flags: %04x qdcount: %d ancount: %d, nscount: %d, arcount: %d\n",
                         ph[P_ID], ph[P_FLAGS], ph[P_QDCOUNT], ph[P_ANCOUNT], ph[P_NSCOUNT], ph[P_ARCOUNT]);
  if (cb->process_header) {
    cb->process_header(arg, ph[P_ID], ph[P_FLAGS], 0x200 & ph[P_FLAGS], 0xF & ph[P_FLAGS],
                            ph[P_QDCOUNT], ph[P_ANCOUNT], ph[P_NSCOUNT], ph[P_ARCOUNT]);
  }
  for(i=0; i<ph[P_QDCOUNT]; i++) {
    assert(&pstate == ps);
    assert(!ps->err);
    if(decode_question(ps, namebuf, &type, &class)) {
      return ps->err;
    }
    assert(!ps->err);
    assert(&pstate == ps);
    debug(0, "Q: type: %d class: %d\n", type, class);
    if(cb->process_question) {
      cb->process_question(arg, namebuf, type, class);
    }
    assert(&pstate == ps);
  }
  for(i = P_ANCOUNT; i <= P_ARCOUNT; i++) {
    for(j=0; j<ph[i]; j++) {
      assert(&pstate == ps);
      if(decode_rr(ps, namebuf, &type, &class, &ttl, &rdlength)) {
        return ps->err;
      }
      assert(&pstate == ps);
      debug(0, "RR type: %d, class: %d, ttl: %" PRIx32 ", rdlen: %d\n", type, class, ttl, rdlength);
      /* FIXME: process RDATA according to types. */
      if(get_bytestring(ps, sizeof(rdata), rdlength, rdata)) {
        return ps->err;
      }
      assert(&pstate == ps);
      switch(type) {
        case DNS_T_A:
          if(cb->process_a_rr) {
	    cb->process_a_rr(arg, namebuf, ttl, *((uint32_t *)rdata));
          }
	  break;
        case DNS_T_AAAA:
          if(cb->process_aaaa_rr) {
	    cb->process_aaaa_rr(arg, namebuf, ttl, (uint8_t *)&rdata[0]);
          }
	  break;
        case DNS_T_CNAME:
          if(cb->process_cname_rr) {
            prdata = rdata;
            if(decode_domain(ps, &prdata, sizeof(namebuf2)-1, &namelen2, namebuf2)) {
              return ps->err;
            }
	    cb->process_cname_rr(arg, namebuf, ttl, namebuf2);
          }
	  break;
        case DNS_T_PTR:
          if(cb->process_ptr_rr) {
            prdata = rdata;
            if(decode_domain(ps, &prdata, sizeof(namebuf2)-1, &namelen2, namebuf2)) {
              return ps->err;
            }
	    cb->process_ptr_rr(arg, namebuf, ttl, namebuf2);
          }
	  break;
        case DNS_T_TXT:
          if(cb->process_txt_rr) {
	    if(rdlength < sizeof(rdata)) {
              rdata[rdlength] = 0;
            }
	    cb->process_txt_rr(arg, namebuf, ttl, rdlength, rdata);
          }
          break;
        case DNS_T_SRV:
          if(cb->process_srv_rr) {
            uint16_t prio, weight, port;
            prdata = rdata;
            prio = ntohs(*(uint16_t *)prdata);
            prdata += 2;
            weight = ntohs(*(uint16_t *)prdata);
            prdata += 2;
            port = ntohs(*(uint16_t *)prdata);
            prdata += 2;
            if(decode_domain(ps, &prdata, sizeof(namebuf2)-1, &namelen2, namebuf2)) {
              return ps->err;
            }
	    cb->process_srv_rr(arg, namebuf, ttl, prio, weight, port, namebuf2);
          }
	  break;

      }
    }
  }
  printf("Err: %d\n", ps->err);
  return ps->err;
}

int ydns_decode_reply(unsigned char *buf, int buflen, void *arg, decode_callbacks_t *cb) {
  return ydns_decode_packet(buf, buflen, arg, cb);
}
