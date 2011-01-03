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


char buf[32768];

int store_8(char **pp, char *pe, uint8_t val) {
  if(*pp == pe) {
    return 0;
  } else {
    *(*pp)++ = val;
    return 1;
  }
}
int store_16(char **pp, char *pe, uint16_t val) {
  return (store_8(pp, pe, val >> 8) && store_8(pp, pe, val & 0xff));
}

int store_str(char **pp, char *pe, char *str) {
  char *pce = str;
  char *pc = str;
  int len;
  while(*pc && (*pp < pe)) {
    /* find the length of the next name segment */
    for(len=0, pce=pc; ((len < 64) && (*pce) && (*pce != '.')); pce++, len++);
    debug(STORE_STR, "Seg len: %d (len: %d)\n", pce-pc, len);
    if(len > 63) { return 0; }
    /* try to store this name segment to target buffer */
    if(store_8(pp, pe, (uint8_t) len)) {
      while(pce != pc) {
        debug(STORE_STR, "storing '%c'\n", *pc);
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

int encode_request(char **buf, int buf_sz, int type, char *name) {
  char *p = *buf;
  char *pe = p + buf_sz;
  uint16_t id = 0x1234;
  /* +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+ 
      0   0  0  0  0  0  0  1  0  0 0  0  0  0  0  0   */
  uint16_t opcode_flags = 0b0000000100000000;
  uint16_t qdcount = 1;
  uint16_t ancount = 0;
  uint16_t nscount = 0;
  uint16_t arcount = 0;
  uint16_t qtype = type;
  uint16_t qclass = 1;
  
  int result = 1;

  debug("Encoding start, p:%p, pe: %p\n", p, pe);

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

int main() {
  int sock;
  struct sockaddr_in server_addr;
  struct hostent *host;
  char send_data[1024] = "api.twitter.com";
  char *p = buf;
  int enclen;
  int nread;
  int sockaddr_sz = sizeof(struct sockaddr);

  host= (struct hostent *) gethostbyname((char *)"192.168.1.1");


  if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
    perror("socket");
    exit(1);
  }

  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(53);
  server_addr.sin_addr = *((struct in_addr *)host->h_addr);
  bzero(&(server_addr.sin_zero),8);
  if(encode_request(&p, sizeof(buf), 0x1, send_data)) {
        enclen = p-buf; 
        sendto(sock, buf, enclen, 0,
              (struct sockaddr *)&server_addr, sizeof(struct sockaddr));
        printf("Waiting for reply...\n");
        sockaddr_sz = sizeof(struct sockaddr);
	nread = recvfrom(sock, buf, sizeof(buf), 0,
	      (struct sockaddr *)&server_addr, &sockaddr_sz); 
        printf("Parse result: %d\n", parse_dns_reply(buf, nread));
  } else {
        printf("Could not encode name!\n");
  }
}

