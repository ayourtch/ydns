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
#include <sys/poll.h>
#include <time.h>
#include <netinet/icmp6.h>
#include "dns.h"

unsigned char send_buf[1500];
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

#define ICMP6_COOKIES 0x42
#define ICMP6_COOKIES_SET_COOKIE 0x1
#define ICMP6_COOKIES_UNEXPECTED_SET_COOKIE 0x02


void send_cookies(uint8_t msg_code, uint32_t cookie, uint32_t cookie2, struct sockaddr_in6 v6_addr) {
  uint8_t buf[64];
  struct icmp6_hdr *icmp = (void *)buf;
  uint32_t *pcookie2 = (void *)(icmp+1);

  int fd = socket(PF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
  socklen_t sockaddr_sz = sizeof(struct sockaddr_in6);

  memset(buf, 'x', sizeof(buf));

  icmp->icmp6_type = ICMP6_COOKIES;
  icmp->icmp6_code = msg_code;
  icmp->icmp6_data32[0] = htonl(cookie);
  *pcookie2 = htonl(cookie2);

  sendto(fd, buf, sizeof(buf), 0, (struct sockaddr *)&v6_addr, sockaddr_sz);
  perror("cookies sendto");
  close(fd);
}

void set_option(int sock, uint8_t optnum, uint32_t optval) {
  int on = 1;
  uint8_t optbuf[128];
  int extlen = 8;
  void *popt;
  void *pbuf = optbuf;
  int totlen;
  int res;
  int i;
  uint32_t optval_n = htonl(optval);
  int opt_len = 4;

  struct ip6_dest *dst = (void *)optbuf;
  dst->ip6d_nxt = 17;
  dst->ip6d_len = 1;

  // setsockopt(sock, IPPROTO_IPV6, IPV6_RECVDSTOPTS,  &on, sizeof(on));
  printf("Setting option number %02x to value %08x\n", optnum, optval);
  totlen = inet6_opt_finish(optbuf, extlen, inet6_opt_append(optbuf, extlen, inet6_opt_init(optbuf, extlen), optnum, 4, 4, &popt));
  inet6_opt_set_val(popt, 0, &optval_n, sizeof(optval_n));
  pbuf = optbuf;
  for(i=0;i<totlen;i++) {
    printf(" %02x", optbuf[i]);
  }
  printf("\n");
  if(setsockopt(sock, IPPROTO_IPV6, IPV6_DSTOPTS, optbuf, totlen)) {
    perror("setsockopt IPV6_DSTOPTS");
  }
}



int main(int argc, char *argv[]) {
  int sock;
  int icmp_sock;
  struct sockaddr_in6 server_addr;
  struct sockaddr_in6 icmp_src_addr;
  struct sockaddr_in6 reply_src_addr;
  unsigned char *p = send_buf;
  int enclen;
  int nread;
  socklen_t sockaddr_sz = sizeof(struct sockaddr);
  int misc_opt = 5;
  int using_option = 0;
  int have_reply = 0;
  uint32_t cookie;
  uint8_t optnum;

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
  if ((icmp_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) == -1) {
    perror("icmp socket");
    exit(1);
  }


  while (misc_opt < argc) {
    if (0 == strcmp(argv[misc_opt], "option")) {
      uint32_t optval = 42;
      optnum = strtol(argv[misc_opt+1], NULL, 0);
      if (misc_opt + 2 < argc) {
        optval = strtol(argv[misc_opt+2], NULL, 0);
      }
      cookie = optval;
      set_option(sock, optnum, optval);
      using_option = 1;
      misc_opt += 2;
    } else if (0 == strcmp(argv[misc_opt], "hoplimit")) {
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

  sockaddr_sz = sizeof(struct sockaddr);
  bzero(&server_addr, sizeof(server_addr));
  server_addr.sin6_family = AF_INET6;
  server_addr.sin6_port = htons(atoi(argv[2]));
  inet_pton(AF_INET6, argv[1], &server_addr.sin6_addr);
  if(ydns_encode_request(&p, sizeof(send_buf), atoi(argv[3]), argv[4], 0x1234)) {
    enclen = p-send_buf;
    if (using_option) {
      struct pollfd pfd[2];
      time_t time_start = time(NULL);
      int nfds;
      printf("Using option; sent the request\n");
      sendto(sock, send_buf, enclen, 0,
        (struct sockaddr *)&server_addr, sizeof(server_addr));
      pfd[0].fd = sock;
      pfd[1].fd = icmp_sock;
      pfd[0].events = pfd[1].events = POLLIN;
#define FALLBACK_TIMEOUT_MS 500
      while(time_start + 1 > time(NULL)) {
        int i;
        nfds = poll(pfd, 2, FALLBACK_TIMEOUT_MS);
        printf("poll nfds: %d\n", nfds);
        if(pfd[0].revents & POLLIN) {
          nread = recvfrom(sock, buf, sizeof(buf), 0,
            (struct sockaddr *)&server_addr, &sockaddr_sz);
          have_reply = 1;
          break;
        }
        if(pfd[1].revents & POLLIN) {
          struct icmp6_hdr *icmp = (void *)buf;
          nread = recvfrom(icmp_sock, buf, sizeof(buf), 0,
            (struct sockaddr *)&icmp_src_addr, &sockaddr_sz);
          printf("Got ICMP: %d\n", icmp->icmp6_type);
          if (icmp->icmp6_type == ICMP6_COOKIES && icmp->icmp6_code == ICMP6_COOKIES_SET_COOKIE) {
            uint32_t suggested_cookie = ntohl(icmp->icmp6_data32[0]);
            uint32_t *pmy_cookie = (void *)(icmp + 1);
            printf("I sent %08x, they ask to send %08x!\n", cookie, suggested_cookie);
            if (ntohl(*pmy_cookie) == cookie) {
              printf("sent_cookie matches mine, let's retry with the suggested cookie\n");
              cookie = suggested_cookie;
              set_option(sock, optnum, cookie);
              sendto(sock, send_buf, enclen, 0,
                  (struct sockaddr *)&server_addr, sizeof(server_addr));
              perror("sock_resend_with_cookie");
            } else {
              printf("They sent me the sent_cookie which is not mine. Someone spoofed my source ?\n");
              send_cookies(ICMP6_COOKIES_UNEXPECTED_SET_COOKIE, 0, suggested_cookie, server_addr);
            }
          }
        }
      }
    }
    if(using_option) {
      /* clear the cookie option */
      close(sock);
      if ((sock = socket(AF_INET6, SOCK_DGRAM, 0)) == -1) {
        perror("socket");
        exit(1);
      }
    }
    sockaddr_sz = sizeof(struct sockaddr);
    if (!have_reply) {
      printf("Send the request again\n");
      sendto(sock, send_buf, enclen, 0,
        (struct sockaddr *)&server_addr, sizeof(server_addr));
      perror("sendto");
      alarm(3);
      printf("Waiting for reply on request...\n");
      nread = recvfrom(sock, buf, sizeof(buf), 0,
         (struct sockaddr *)&server_addr, &sockaddr_sz);
    }
    printf("Parse result: %d\n", ydns_decode_reply(buf, nread, (void *)0xdeadbeef, &my_cb));
  } else {
        printf("Could not encode name!\n");
  }
  return 0;
}

