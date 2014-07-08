#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "dns.h"

typedef struct parse_state {
  char *p;
  char *pe;
  int ok;
} parse_state_t;

typedef void (*char_store_cb_t)(char c);

char decode_char(parse_state_t *ps) {
  return 0;
}

int decode_label(parse_state_t *ps, void *arg, char_store_cb_t cb) {
  char len;
  char c;
  for(len = decode_char(ps); ps->ok && (len > 0); len--) {
    c = decode_char(ps);
    if(ps->ok) {
      cb(c);
    } else {
      return 0;
    }
  }
  return(ps->ok);
}

int ydns_decode_reply(unsigned char *buf, int buflen, void *arg, decode_callbacks_t *cb) { 

  return 0;
}
