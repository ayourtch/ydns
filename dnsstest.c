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
#include <netinet/icmp6.h>
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
  .process_srv_rr = my_srv_rr,
};

#define ICMP6_COOKIES 0x42
#define ICMP6_COOKIES_SET_COOKIE 0x1

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
}

#define IPV6_ADD_MEMBERSHIP IPV6_JOIN_GROUP

int main(int argc, char *argv[]) {
  int sock;
  char str_addr[1024];
  struct sockaddr_in6 v6_addr;
  struct sockaddr_in *pv4_addr;
  unsigned char *p = buf;
  unsigned char *pe = p + sizeof(buf);
  int enclen;
  int nread;
  int result;
  int listen_port;
  socklen_t sockaddr_sz;

  if(argc < 3) {
    printf("Usage: %s <bind-addr> <port>\n", argv[0]);
    exit(1);
  }


  if ((sock = socket(AF_INET6, SOCK_DGRAM, 0)) == -1) {
    perror("socket");
    exit(1);
  }
  { /* Reuse the port even if another mDNS server is running */
    int yes = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
  }
  listen_port = atoi(argv[2]);
  bzero(&v6_addr, sizeof(v6_addr));
  v6_addr.sin6_family = AF_INET6;
  v6_addr.sin6_port = htons(listen_port);
  inet_pton(AF_INET6, argv[1], &v6_addr.sin6_addr);
  if (0 > bind(sock, (struct sockaddr *)&v6_addr, sizeof(v6_addr))) {
    perror("bind");
    exit(1);
  }
  if (5353 == listen_port) {
    struct ipv6_mreq mreq;  /* Multicast address join structure */
    struct ip_mreq mreq4;
    printf("You specified the port 5353, I will try to join the multicast group ff02::fb\n");
    inet_pton(AF_INET6, "ff02::fb", &v6_addr.sin6_addr);
    memcpy(&mreq.ipv6mr_multiaddr,
           &((struct sockaddr_in6*)(&v6_addr))->sin6_addr,
               sizeof(mreq.ipv6mr_multiaddr));
    /* Accept from any interface */
    mreq.ipv6mr_interface = 0;
    if ( setsockopt(sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char*) &mreq, sizeof(mreq)) != 0 ) {
      printf("Error joining multicast group\n");
    }
    inet_pton(AF_INET, "224.0.0.251", &mreq4.imr_multiaddr);
    /* Accept from any interface */
    mreq4.imr_interface.s_addr = 0;
    if ( setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*) &mreq4, sizeof(mreq4)) != 0 ) {
      printf("Error joining v4 multicast group\n");
    }
  }
  if (53 == listen_port) {
    int on = 1;
    setsockopt(sock, IPPROTO_IPV6, IPV6_RECVDSTOPTS, &on, sizeof(on));
  }

  while (1) {
      uint8_t optbuf[256];
      uint8_t *p8;
      struct cmsghdr *cmsgptr= (void*)optbuf;
      int i;
      uint32_t cookie;

      struct iovec iov[1];
      iov[0].iov_base=buf;
      iov[0].iov_len=sizeof(buf);

      struct msghdr message;
      message.msg_name=&v6_addr;
      message.msg_namelen=sizeof(v6_addr);
      message.msg_iov=iov;
      message.msg_iovlen=1;
      message.msg_control=optbuf;
      message.msg_controllen=sizeof(optbuf);

      printf("Waiting for a request...\n");
      nread = recvmsg(sock, &message, 0);
      if (nread == -1) {
	printf("error: %s",strerror(errno));
        exit(1);
      } else if (message.msg_flags&MSG_TRUNC) {
	printf("datagram too large for buffer: truncated and ignored\n");
        continue;
      }
      if (message.msg_controllen != 0 && cmsgptr->cmsg_level == IPPROTO_IPV6 && cmsgptr->cmsg_type == IPV6_DSTOPTS) {
        void *optdata;
        uint8_t opttype;
        socklen_t optlen;

        int ret = inet6_opt_next(CMSG_DATA(cmsgptr), cmsgptr->cmsg_len - sizeof(struct cmsghdr), 0, &opttype, &optlen, &optdata);
        p8 = optdata; // CMSG_DATA(cmsgptr);
        for (i=0;i<20;i++){ 
          printf(" %02x", p8 ? p8[i] : 0);
        }
        printf("\n");
        printf("Got some options, cmsg len: %d, opt_next result: %d, opttype: %02x, optlen: %d!\n", cmsgptr->cmsg_len, ret, opttype, optlen);
        inet6_opt_get_val(optdata, 0, &cookie, sizeof(cookie));
        printf("Cookie: %08x\n", ntohl(cookie));
#define MOCK_COOKIE 0x12345678
        if (MOCK_COOKIE != ntohl(cookie)) {
          send_cookies(ICMP6_COOKIES_SET_COOKIE, MOCK_COOKIE, ntohl(cookie), v6_addr);
          continue;
        } else {
          printf("Cookie is correct!\n");
        }
      }

      sockaddr_sz = sizeof(v6_addr);
      /*
      nread = recvfrom(sock, buf, sizeof(buf), 0,
	      (struct sockaddr *)&v6_addr, &sockaddr_sz); 
      */
      printf("Got %d bytes request, family: %d (%d/%d)..\n", nread, v6_addr.sin6_family, AF_INET, AF_INET6);
      if (AF_INET == v6_addr.sin6_family) {
        printf("IPv4 pkt on IPv4-mapped address socket, convert sockaddr into IPv6 for sendto\n");
        pv4_addr = (void *)&v6_addr;
        snprintf(str_addr, sizeof(str_addr)-1, "::ffff:%s", inet_ntoa(pv4_addr->sin_addr));
        v6_addr.sin6_family = AF_INET6;
        inet_pton(AF_INET6, str_addr, &v6_addr.sin6_addr);
	sockaddr_sz = sizeof(struct sockaddr_in6);
      }
      if (AF_INET6 == v6_addr.sin6_family) {
        char src[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &v6_addr.sin6_addr, src, INET6_ADDRSTRLEN);
        printf("Src: %s\n", src);
      } 
      result = ydns_decode_reply(buf, nread, (void *)0xdeadbeef, &my_cb);
      printf("Parse result: %d\n", result);
      if (0 == result) {
        int nans = 0;
	p = buf;
	if ( (question_type == 28) || (question_type == 1) || (question_type == 16)) {
	  nans++;
        }
	result = ydns_encode_pdu(&p, sizeof(buf), question_type, question_name, question_id,
		nans > 0 ? 0x8400 : 0x8400, 1, nans, 1, 0, question_class);
	if (question_type == 1) {
	  result = result && ydns_encode_rr_start(&p, (pe-p), question_name, question_type, 1, 0x5000);
	  result = result && ydns_encode_rr_data(&p, (pe-p), "\xc0\000\002\001", 4);
	} else if (question_type == 28) {
	  result = result && ydns_encode_rr_start(&p, (pe-p), question_name, question_type, 1, 0x5000);
	  result = result && ydns_encode_rr_data(&p, (pe-p), "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", 16);
	} else if (question_type == 16) {
	  result = result && ydns_encode_rr_start(&p, (pe-p), question_name, question_type, 1, 0x5000);
	  result = result && ydns_encode_rr_data(&p, (pe-p), "\011some text", 10);
        }
	result = result && ydns_encode_rr_start(&p, (pe-p), "sub.stdio.be", 6, 1, 0x5000);
	result = result && ydns_encode_rr_soa(&p, (pe-p), "sub.stdio.be", "root.sub.stdio.be",
						12345, 86400, 7200, 604800, 86400);
        if(result) {
	  sendto(sock, buf, (p - buf), 0, (struct sockaddr *)&v6_addr, sockaddr_sz);
	  perror("sendto");
        }
      }
  }
  
  return 0;
}

