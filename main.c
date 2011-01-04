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
  struct sockaddr_in server_addr;
  struct hostent *host;
  unsigned char *p = buf;
  int enclen;
  int nread;
  socklen_t sockaddr_sz = sizeof(struct sockaddr);

  if(argc < 4) {
    printf("Usage: %s <recursive DNS> <type> <DNS name>\n", argv[0]);
    exit(1);
  }

  host= (struct hostent *) gethostbyname((char *)argv[1]);


  if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
    perror("socket");
    exit(1);
  }

  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(53);
  server_addr.sin_addr = *((struct in_addr *)host->h_addr);
  bzero(&(server_addr.sin_zero),8);
  if(ydns_encode_request(&p, sizeof(buf), atoi(argv[2]), argv[3], 0x1234)) {
        enclen = p-buf; 
        sendto(sock, buf, enclen, 0,
              (struct sockaddr *)&server_addr, sizeof(struct sockaddr));
        printf("Waiting for reply...\n");
        sockaddr_sz = sizeof(struct sockaddr);
	nread = recvfrom(sock, buf, sizeof(buf), 0,
	      (struct sockaddr *)&server_addr, &sockaddr_sz); 
        printf("Parse result: %d\n", ydns_decode_reply(buf, nread, NULL));
  } else {
        printf("Could not encode name!\n");
  }
  return 0;
}

