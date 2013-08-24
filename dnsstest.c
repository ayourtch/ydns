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

unsigned char buf[1500];

char question_name[2048];
int question_type;
int question_class;
int question_id;

char *safe_cpy(char *dst, char *src, int sizeofdst) {
  strncpy(dst, src, sizeofdst-1);
  dst[sizeofdst-1] = 0;
  return dst;
}

static int my_header(void *arg, int req_id, int flags, int trunc, int errcode, int qdcount, int ancount, int nscount, int arcount) {
  printf("Header: req_id: %d, flags: %x, trunc: %d; errcode: %d, qdcount: %d, ancount: %d, nscount: %d, arcount: %d\n",
          req_id, flags, trunc, errcode, qdcount, ancount, nscount, arcount);
  question_id = req_id;
  return 1;
}
static int my_question(void *arg, char *domainname, int type, int class) {
  printf("Question: Name: '%s', type: %d, class: %d\n", domainname, type, class);
  safe_cpy(question_name, domainname, sizeof(question_name));
  question_type = type;
  question_class = class;
  return 1;
}
static int my_a_rr(void *arg, char *domainname, uint32_t ttl, uint32_t addr) {
  char dest[INET_ADDRSTRLEN+1] = { 0 };
  inet_ntop(AF_INET, &addr, dest, sizeof(dest));
  printf("RR A: '%s' => %s (ttl: %d)\n", domainname, dest, ttl);
  return 1;
}
static int my_aaaa_rr(void *arg, char *domainname, uint32_t ttl, uint8_t *addr) {
  char dest[INET6_ADDRSTRLEN+1] = { 0 };
  inet_ntop(AF_INET6, addr, dest, sizeof(dest));
  printf("RR AAAA: '%s' => %s (ttl: %d)\n", domainname, dest, ttl);
  return 1;
}
static int my_cname_rr(void *arg, char *domainname, uint32_t ttl, char *cname) {
  printf("RR CNAME: '%s' => %s (ttl: %d)\n", domainname, cname, ttl);
  return 1;
}
static int my_ptr_rr(void *arg, char *domainname, uint32_t ttl, char *cname) {
  printf("RR PTR: '%s' => %s (ttl: %d)\n", domainname, cname, ttl);
  return 1;
}


decode_callbacks_t my_cb = {
  .process_header = my_header,
  .process_question = my_question,
  .process_a_rr = my_a_rr,
  .process_aaaa_rr = my_aaaa_rr,
  .process_cname_rr = my_cname_rr,
  .process_ptr_rr = my_ptr_rr,
};

int main(int argc, char *argv[]) {
  int sock;
  struct sockaddr_in6 server_addr;
  unsigned char *p = buf;
  unsigned char *pe = p + sizeof(buf);
  int enclen;
  int nread;
  int result;
  socklen_t sockaddr_sz = sizeof(struct sockaddr);

  if(argc < 3) {
    printf("Usage: %s <bind-addr> <port>\n", argv[0]);
    exit(1);
  }


  if ((sock = socket(AF_INET6, SOCK_DGRAM, 0)) == -1) {
    perror("socket");
    exit(1);
  }

  bzero(&server_addr, sizeof(server_addr));
  server_addr.sin6_family = AF_INET6;
  server_addr.sin6_port = htons(atoi(argv[2]));
  inet_pton(AF_INET6, argv[1], &server_addr.sin6_addr);
  if (0 > bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr))) {
    perror("bind");
    exit(1);
  }

  while (1) {
      printf("Waiting for a request...\n");
      sockaddr_sz = sizeof(struct sockaddr);
      nread = recvfrom(sock, buf, sizeof(buf), 0,
	      (struct sockaddr *)&server_addr, &sockaddr_sz); 
      printf("Got %d bytes request..\n", nread);
      result = ydns_decode_reply(buf, nread, (void *)0xdeadbeef, &my_cb);
      printf("Parse result: %d\n", result);
      if (11 == result) {
	p = buf;
	result = ydns_encode_pdu(&p, sizeof(buf), question_type, question_name, question_id,
		0x8403, 1, 0, 1, 0, question_class);
	result = result && ydns_encode_rr_start(&p, (pe-p), "sub.stdio.be", 6, 1, 0x5000);
	result = result && ydns_encode_rr_soa(&p, (pe-p), "sub.stdio.be", "root.sub.stdio.be",
						12345, 86400, 7200, 604800, 86400);
        if(result) {
	  sendto(sock, buf, (p - buf), 0, (struct sockaddr *)&server_addr, sockaddr_sz);
        }
      }
  }
  
  return 0;
}

