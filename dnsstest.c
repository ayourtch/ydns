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


int main(int argc, char *argv[]) {
  int sock;
  struct sockaddr_in6 server_addr;
  unsigned char *p = buf;
  int enclen;
  int nread;
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
  }
  
  return 0;
}

