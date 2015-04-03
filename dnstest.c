#include <sys/types.h>
#include <sys/socket.h>
#define __APPLE_USE_RFC_3542
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

struct ip6_dest {
                     u_int8_t ip6d_nxt;      /* next header */
                     u_int8_t ip6d_len;      /* length in units of 8 octets */
             /* followed by options */
             } __packed;


static int my_header(void *arg, int req_id, int flags, int trunc, int errcode, int qdcount, int ancount, int nscount, int arcount) {
  printf("Header: req_id: %d, flags: %x, trunc: %d; errcode: %d, qdcount: %d, ancount: %d, nscount: %d, arcount: %d\n",
          req_id, flags, trunc, errcode, qdcount, ancount, nscount, arcount);
  return 1;
}
static int my_question(void *arg, char *domainname, int type, int class) {
  printf("Question: Name: '%s', type: %d, class: %d\n", domainname, type, class);
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

static int my_txt_rr(void *arg, char *domainname, uint32_t ttl, uint16_t len, char *text) {
  printf("RR TXT: '%s' => %s (ttl: %d)\n", domainname, text, ttl);
  return 1;
}


static int my_srv_rr(void *arg, char *domainname, uint32_t ttl, uint16_t prio, uint16_t weight, uint16_t port, char *name) {
  printf("SRV PTR: '%s' => %s : %d (prio: %d, weight: %d) (ttl: %d)\n", domainname, name, port, prio, weight, ttl);
  return 1;
}



decode_callbacks_t my_cb = {
  .process_header = my_header,
  .process_question = my_question,
  .process_a_rr = my_a_rr,
  .process_aaaa_rr = my_aaaa_rr,
  .process_cname_rr = my_cname_rr,
  .process_ptr_rr = my_ptr_rr,
  .process_txt_rr = my_txt_rr,
  .process_srv_rr = my_srv_rr,
};



int main(int argc, char *argv[]) {
  int sock;
  struct sockaddr_in6 server_addr;
  unsigned char *p = buf;
  int enclen;
  int nread;
  socklen_t sockaddr_sz = sizeof(struct sockaddr);
  int misc_opt = 5;

  if(argc < 5) {
    printf("Usage: %s <recursive DNS> <port> <record type> <DNS name>\n", argv[0]);
    printf("To query mDNS, use ff02::fb 5353 as server and port.\n");
    printf("Some useful record types:\n");
    printf("    AAAA        28    RFC3596\n");
    printf("    A            1    RFC1035\n");
    printf("    SOA          6    RFC1035 and RFC2308\n");
    printf("    CNAME        5    RFC1035\n");
    printf("    MX          15    RFC1035\n");
    printf("    TXT         16    RFC1035\n");
    printf("    SRV         33    RFC2782\n");
    printf("    NAPTR       35    RFC3404\n");
    printf("    CAA        257    RFC6844\n");
    printf("    CERT        37    RFC4398\n");
    printf("    DNSKEY      48    RFC4034\n");
    printf("    DS          43    RFC4034\n");
    printf("    IPSECKEY    45    RFC4025\n");
    printf("    KEY         25    RFC2535 and RFC2930\n");
    printf("    LOC         29    RFC1876\n");
    printf("    NS           2    RFC1035\n");
    printf("    NSEC        47    RFC4043\n");
    printf("    NSEC3       50    RFC5155\n");
    printf("    NSEC3PARAM  51    RFC5155\n");
    printf("    PTR         12    RFC1035\n");
    printf("    RRSIG       46    RFC4034\n");
    printf("    SIG         24    RFC2535\n");
    printf("    SPF         99    RFC4408\n");
    printf("    SSHFP       44    RFC4255\n");
    printf("    TKEY       249    RFC2930\n");
    printf("    TLSA        52    RFC6698\n");
    printf("    TSIG       250    RFC2845\n");
    exit(1);
  }


  if ((sock = socket(AF_INET6, SOCK_DGRAM, 0)) == -1) {
    perror("socket");
    exit(1);
  }
  while (misc_opt < argc) {
    if (0 == strcmp(argv[misc_opt], "hoplimit")) {
      int  hoplimit = strtol(argv[misc_opt+1], NULL, 0);
      if (setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
                  (char *) &hoplimit, sizeof(hoplimit)) == -1) {
        perror("setsockopt IPV6_UNICAST_HOPS");
      }
      misc_opt += 2;
    } else {
      misc_opt++;
    }
  }

  bzero(&server_addr, sizeof(server_addr));
  server_addr.sin6_family = AF_INET6;
  server_addr.sin6_port = htons(atoi(argv[2]));
  inet_pton(AF_INET6, argv[1], &server_addr.sin6_addr);
  if(ydns_encode_request(&p, sizeof(buf), atoi(argv[3]), argv[4], 0x1234)) {
        enclen = p-buf;
        sendto(sock, buf, enclen, 0,
              (struct sockaddr *)&server_addr, sizeof(server_addr));
	alarm(3);
        printf("Waiting for reply...\n");
        sockaddr_sz = sizeof(struct sockaddr);
	nread = recvfrom(sock, buf, sizeof(buf), 0,
	      (struct sockaddr *)&server_addr, &sockaddr_sz);
        printf("Parse result: %d\n", ydns_decode_reply(buf, nread, (void *)0xdeadbeef, &my_cb));
  } else {
        printf("Could not encode name!\n");
  }
  return 0;
}

