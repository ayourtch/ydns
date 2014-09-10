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
#include <sqlite3.h>
#include <ctype.h>
#include <time.h>

#include "dns.h"

unsigned char buf[1500];
unsigned char sendbuf[1500];

char question_name[2048];
int question_type;
int question_class;
int question_id;

enum { 
  QUERY_FORWARD = 0,
  QUERY_REVERSE, 
  QUERY_SRC_RECORDS,
  QUERY_SRC_CACHE
};

typedef struct {
  sqlite3 *db;
  unsigned char *buf;
  unsigned char *p;
  unsigned char *pe;
  int is_mdns;
  int nquest;
  int nans; 
  int naddtl;
  int nauth;
  int result;
} dns_proc_context_t; 


char *safe_cpy(char *dst, char *src, int sizeofdst) {
  strncpy(dst, src, sizeofdst-1);
  dst[sizeofdst-1] = 0;
  return dst;
}

int set_db_value(dns_proc_context_t *ctx, char *name, int class, int type, char *value, int vlan, int expire, int info_source) {
  int res;
  int ret = 0;
  sqlite3_stmt *stmt = NULL;
  char *sql_cache = "insert into cache values(?1, ?2, ?3, ?4, ?5, ?6);";
  char *sql_rec = "insert into records values(?1, ?2, ?3, ?4, ?5, ?6);";
  char *sql = (QUERY_SRC_CACHE == info_source) ? sql_cache : sql_rec;

  printf("Inserting '%s' => '%s' (type %d) into DB with expire %d on vlan %d..\n", name, value, type, expire, vlan);
  res = sqlite3_prepare_v2(ctx->db, sql, strlen(sql), &stmt, NULL);
  printf("res1: %d\n", res);
  res = sqlite3_bind_text(stmt, 1, name, strlen(name), SQLITE_TRANSIENT);
  printf("res2: %d\n", res);
  res = sqlite3_bind_int(stmt, 2, class);
  printf("res3: %d\n", res);
  res = sqlite3_bind_int(stmt, 3, type);
  printf("res3: %d\n", res);
  res = sqlite3_bind_int(stmt, 4, vlan);
  printf("res3: %d\n", res);
  res = sqlite3_bind_int(stmt, 5, expire);
  printf("res3: %d\n", res);
  res = sqlite3_bind_text(stmt, 6, value, strlen(value), SQLITE_TRANSIENT);
  printf("res3: %d\n", res);
  res = sqlite3_step(stmt);
  printf("res4: %d\n", res);
  printf("Out: %s\n", sqlite3_column_text(stmt, 0));
   
  res = sqlite3_finalize(stmt);
  printf("res5: %d\n", res);
  return ret; 
  
}

int get_db_value(dns_proc_context_t *ctx, char *name, int type, char *out, int outsz, int query_type, int info_source) {
  int res;
  int ret = 0;
  sqlite3_stmt *stmt = NULL;
  char *sql_forward_rec = "select value from records where name = ?1 and type = ?2;";
  char *sql_reverse_rec = "select name from records where value = ?1 and type = ?2;";
  char *sql_forward_cache = "select value from cache where name = ?1 and type = ?2;";
  char *sql_reverse_cache = "select name from cache where value = ?1 and type = ?2;";
  char *sql_forward = info_source == QUERY_SRC_CACHE ? sql_forward_cache : sql_forward_rec;
  char *sql_reverse = info_source == QUERY_SRC_CACHE ? sql_reverse_cache : sql_reverse_rec;
  char *sql = (query_type == QUERY_FORWARD) ? sql_forward : sql_reverse;

  printf("Checking the '%s' type %d in DB..\n", name, type);
  res = sqlite3_prepare_v2(ctx->db, sql, strlen(sql), &stmt, NULL);
  printf("res1: %d\n", res);
  res = sqlite3_bind_text(stmt, 1, name, strlen(name), SQLITE_TRANSIENT);
  printf("res2: %d\n", res);
  res = sqlite3_bind_int(stmt, 2, type);
  printf("res3: %d\n", res);
  res = sqlite3_step(stmt);
  printf("res4: %d\n", res);
  printf("Out: %s\n", sqlite3_column_text(stmt, 0));
  if (res == SQLITE_ROW) {
    safe_cpy(out, (void *)sqlite3_column_text(stmt, 0), outsz);
    ret = 1;
  }
  res = sqlite3_finalize(stmt);
  printf("res5: %d\n", res);
  return ret; 
}

static int my_header(void *arg, int req_id, int flags, int trunc, int errcode, int qdcount, int ancount, int nscount, int arcount) {
  dns_proc_context_t *ctx = arg;
  printf("Header: req_id: %d, flags: %x, trunc: %d; errcode: %d, qdcount: %d, ancount: %d, nscount: %d, arcount: %d\n",
          req_id, flags, trunc, errcode, qdcount, ancount, nscount, arcount);
  question_id = req_id;
  ctx->result = ydns_encode_pdu_start(&ctx->p, ctx->pe - ctx->p);
  printf("After header processing: %d long\n", (int)(ctx->p - ctx->buf));
  return 1;
}

int is_reverse_v6_query(char *query, struct in6_addr *v6_addr) {
  /* 3.9.e.5.3.a.8.9.b.6.b.0.8.3.8.0.e.2.6.0.3.1.f.1.0.7.4.0.1.0.0.2.ip6.arpa. */
  char *v6revdom = ".ip6.arpa.";
  char *pe = strstr(query, v6revdom);
  char *p = query;
  char v6addr_text_full[INET6_ADDRSTRLEN];
  int i = 0;
  int res;
  char *pt = v6addr_text_full;
  if (!pe || strcasecmp(pe, v6revdom) || ( (2*32+9) != strlen(query))) {
    /* match for the IPv6 reverse domain either not found or not the end of string */
    return 0;
  }
  while (pe > p) {
    /* Move to the previous character */
    pe--;
    if(!isxdigit(*pe)) {
      return 0;
    }
    /* Store the next hex digit and move to the next dot */
    *pt++ = *pe--; 
    if (*pe != '.') {
      return 0;
    }
    /* Every 4 hex chars is a colon */
    if(0 == ++i % 4) {
      *pt++ = ':';
    }
  }
  *pt++ = 0;
  printf("IPv6 reverse query, full IPv6 txt form: '%s'\n", v6addr_text_full);
  res = inet_pton(AF_INET6, v6addr_text_full, &v6_addr);
  return (1 == res);
}

int is_reverse_v4_query(char *query, struct in_addr *v4_addr) {
  /* 67.1.168.192.in-addr.arpa. */
  char *v4revdom = ".in-addr.arpa.";
  char *pe = strstr(query, v4revdom);
  char *p = query;
  char *pnext;
  int i;
  uint8_t v4a[4];
  int octet;
  if (!pe) {
    return 0;
  }
  for(i=0; i<4; i++) {
    octet = strtol(p, &pnext, 10);
    if ((octet < 0) || (octet > 255)) {
      return 0;
    }
    if(*pnext != '.') {
      return 0;
    }
    v4a[i] = octet;
    p = pnext+1;
  }
  v4_addr->s_addr = htonl(v4a[0] + 256UL * (v4a[1] + 256UL * (v4a[2] + 256UL * v4a[3])));
  return 1;
}

static int my_question(void *arg, char *domainname, int type, int class) {
  dns_proc_context_t *ctx = arg;
  char value_buf[256];
  char mapped_domainname[256];
  char *dot_pos;
  
  printf("Question: Name: '%s', type: %d, class: %d\n", domainname, type, class);
  
  safe_cpy(question_name, domainname, sizeof(question_name));
  safe_cpy(mapped_domainname, domainname, sizeof(mapped_domainname));
  dot_pos = strchr(mapped_domainname, '.');
  if(dot_pos) {
    safe_cpy(dot_pos, ".local.", sizeof(mapped_domainname) - (dot_pos - mapped_domainname));
  }
 
  question_type = type;
  question_class = class;
  if( (!ctx->is_mdns) && (0 == ctx->nquest) ) {
    ydns_encode_question(&ctx->p, ctx->pe - ctx->p, domainname, type, class);
    ctx->nquest++;
  }

  if(question_type == 12) {
    struct in_addr v4_addr;
    struct in6_addr v6_addr;
    /* 
     * We handle the reverse queries here
     */
    if (is_reverse_v6_query(domainname, &v6_addr)) {
      char v6addr_text[INET6_ADDRSTRLEN];
      inet_ntop(AF_INET6, &v6_addr, v6addr_text, INET6_ADDRSTRLEN);
      printf("IPv6 reverse query for '%s'\n", v6addr_text);
      if(get_db_value(ctx, v6addr_text, 28, value_buf, sizeof(value_buf), QUERY_REVERSE, QUERY_SRC_RECORDS)) {
        printf("IPv6 reverse query answer: => '%s'\n", value_buf);
        ctx->result = ctx->result && ydns_encode_rr_start(&ctx->p, (ctx->pe - ctx->p), question_name, question_type, 1, 0x5);
        ctx->result = ctx->result && ydns_encode_rr_data_domain(&ctx->p, (ctx->pe - ctx->p), value_buf);
        ctx->nans++;
      }
    }

    if (is_reverse_v4_query(domainname, &v4_addr)) {
      char v4addr_text[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &v4_addr, v4addr_text, INET_ADDRSTRLEN);
      printf("IPv4 reverse query for '%s'\n", v4addr_text);
      if(get_db_value(ctx, v4addr_text, 1, value_buf, sizeof(value_buf), QUERY_REVERSE, QUERY_SRC_RECORDS)) {
        printf("IPv4 reverse query answer: => '%s'\n", value_buf);
        ctx->result = ctx->result && ydns_encode_rr_start(&ctx->p, (ctx->pe - ctx->p), question_name, question_type, 1, 0x5);
        ctx->result = ctx->result && ydns_encode_rr_data_domain(&ctx->p, (ctx->pe - ctx->p), value_buf);
        ctx->nans++;
      }
    }
  }
  if(get_db_value(ctx, mapped_domainname, question_type, value_buf, sizeof(value_buf), QUERY_FORWARD, ctx->is_mdns ? QUERY_SRC_RECORDS : QUERY_SRC_CACHE)) {
    printf("Found answer in DB: %s\n", value_buf);
    if (question_type == 1) {
      struct in_addr v4_addr;
      int res = inet_pton(AF_INET, value_buf, &v4_addr);
      if (res > 0) {
        ctx->result = ctx->result && ydns_encode_rr_start(&ctx->p, (ctx->pe - ctx->p), question_name, question_type, 1, 0x5);
        ctx->result = ctx->result && ydns_encode_rr_data(&ctx->p, (ctx->pe - ctx->p), &v4_addr, 4);
        ctx->nans++;
        printf("Added A reply\n");
      } else {
        printf("Error adding A reply\n");
      }
    } else if (question_type == 28) {
      struct in6_addr v6_addr;
      int res = inet_pton(AF_INET6, value_buf, &v6_addr);
      if (res > 0) {
        ctx->result = ctx->result && ydns_encode_rr_start(&ctx->p, (ctx->pe - ctx->p), question_name, question_type, 1, 0x5);
        ctx->result = ctx->result && ydns_encode_rr_data(&ctx->p, (ctx->pe - ctx->p), &v6_addr, 16);
        ctx->nans++;
        printf("Added AAAA reply\n");
      } else {
        printf("Error adding AAAA reply\n");
      }
    } else if (question_type == 16) {
      unsigned char record_buf[256];
      record_buf[0] = strlen(value_buf);
      memcpy(record_buf+1, value_buf, record_buf[0]);
      ctx->result = ctx->result && ydns_encode_rr_start(&ctx->p, (ctx->pe - ctx->p), question_name, question_type, 1, 0x5);
      ctx->result = ctx->result && ydns_encode_rr_data(&ctx->p, (ctx->pe - ctx->p), record_buf, record_buf[0]+1);
      ctx->nans++;
      printf("Added TXT reply\n");
    }
  }

  if(strcmp(domainname, "gateway.local.") == 0) {
/*
    ctx->result = ctx->result && ydns_encode_rr_start(&ctx->p, (ctx->pe - ctx->p), "sub.stdio.be", 6, 1, 0x5000);
    ctx->result = ctx->result && ydns_encode_rr_soa(&ctx->p, (ctx->pe - ctx->p), "sub.stdio.be", "root.sub.stdio.be",
						    12345, 86400, 7200, 604800, 86400);
*/
  }
  return 1;
}


static int my_a_rr(void *arg, char *domainname, uint32_t ttl, uint32_t addr) {
  dns_proc_context_t *ctx = arg;
  char dest[INET_ADDRSTRLEN+1] = { 0 };
  time_t now = time(NULL);
  inet_ntop(AF_INET, &addr, dest, sizeof(dest));
  printf("RR A: '%s' => %s (ttl: %d)\n", domainname, dest, ttl);
  set_db_value(ctx, domainname, 1, DNS_T_A, dest, 0, now+ttl, QUERY_SRC_CACHE);
  return 1;
}
static int my_aaaa_rr(void *arg, char *domainname, uint32_t ttl, uint8_t *addr) {
  dns_proc_context_t *ctx = arg;
  char dest[INET6_ADDRSTRLEN+1] = { 0 };
  time_t now = time(NULL);
  inet_ntop(AF_INET6, addr, dest, sizeof(dest));
  printf("RR AAAA: '%s' => %s (ttl: %d)\n", domainname, dest, ttl);
  set_db_value(ctx, domainname, 1, DNS_T_AAAA, dest, 0, now+ttl, QUERY_SRC_CACHE);
  return 1;
}
static int my_cname_rr(void *arg, char *domainname, uint32_t ttl, char *cname) {
  dns_proc_context_t *ctx = arg;
  time_t now = time(NULL);
  printf("RR CNAME: '%s' => %s (ttl: %d)\n", domainname, cname, ttl);
  set_db_value(ctx, domainname, 1, DNS_T_CNAME, cname, 0, now+ttl, QUERY_SRC_CACHE);
  return 1;
}
static int my_ptr_rr(void *arg, char *domainname, uint32_t ttl, char *cname) {
  dns_proc_context_t *ctx = arg;
  time_t now = time(NULL);
  printf("RR PTR: '%s' => %s (ttl: %d)\n", domainname, cname, ttl);
  set_db_value(ctx, domainname, 1, DNS_T_PTR, cname, 0, now+ttl, QUERY_SRC_CACHE);
  return 1;
}

static int my_srv_rr(void *arg, char *domainname, uint32_t ttl, uint16_t prio, uint16_t weight, uint16_t port, char *name) {
  dns_proc_context_t *ctx = arg;
  time_t now = time(NULL);
  #define INT_NUM_MAX 21
  char fullstr[255+3*(1+INT_NUM_MAX)];
  printf("SRV PTR: '%s' => %s : %d (prio: %d, weight: %d) (ttl: %d)\n", domainname, name, port, prio, weight, ttl);
  snprintf(fullstr, sizeof(fullstr), "%d %d %d %s", prio, weight, port, name);
  set_db_value(ctx, domainname, 1, DNS_T_SRV, fullstr, 0, now+ttl, QUERY_SRC_CACHE);
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

#define IPV6_ADD_MEMBERSHIP IPV6_JOIN_GROUP

static int callback(void *NotUsed, int argc, char **argv, char **azColName){
  int i;
  for(i=0; i<argc; i++){
    printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
  }
  printf("\n");
  return 0;
}
 

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
  char *zErrMsg = 0;
  int rc;
  dns_proc_context_t dns_ctx;

  if(argc < 4) {
    printf("Usage: %s <bind-addr> <port> <sqlite.db>\n", argv[0]);
    exit(1);
  }

  listen_port = atoi(argv[2]);
  dns_ctx.is_mdns = (5353 == listen_port) ? 1 : 0;

  rc = sqlite3_open_v2(argv[3], &dns_ctx.db, SQLITE_OPEN_READWRITE, NULL);
  if(rc) {
    char *sql1 = "CREATE TABLE records (name varchar(255), class int, type int, vlan int, expire int, value varchar(255));";
    char *sql2 = "CREATE TABLE cache (name varchar(255), class int, type int, vlan int, expire int, value varchar(255));";

    fprintf(stderr, "Can not open database, trying to create from scratch\n");
    rc = sqlite3_open_v2(argv[3], &dns_ctx.db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    rc = rc || sqlite3_exec(dns_ctx.db, sql1, NULL, 0, NULL);
    rc = rc || sqlite3_exec(dns_ctx.db, sql2, NULL, 0, NULL);

  }
  if(rc) {
    fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(dns_ctx.db));
    sqlite3_close(dns_ctx.db);
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
  bzero(&v6_addr, sizeof(v6_addr));
  v6_addr.sin6_family = AF_INET6;
  v6_addr.sin6_port = htons(listen_port);
  inet_pton(AF_INET6, argv[1], &v6_addr.sin6_addr);
  if (0 > bind(sock, (struct sockaddr *)&v6_addr, sizeof(v6_addr))) {
    perror("bind");
    exit(1);
  }
  if (dns_ctx.is_mdns) {
    struct ipv6_mreq mreq;  /* Multicast address join structure */
    struct ip_mreq mreq4;
    printf("mDNS listener, joining the multicast groups ff02::fb and 224.0.0.251\n");
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
  errno = 0;
  while (1) {
      printf("Waiting for a request...\n");
      sockaddr_sz = sizeof(v6_addr);
      nread = recvfrom(sock, buf, sizeof(buf), 0,
	      (struct sockaddr *)&v6_addr, &sockaddr_sz); 
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
      memset(sendbuf, 0, sizeof(sendbuf));
      dns_ctx.buf = sendbuf;
      dns_ctx.p = sendbuf;
      dns_ctx.pe = dns_ctx.p + sizeof(sendbuf);
      dns_ctx.nquest = 0;
      dns_ctx.nans = 0;
      dns_ctx.nauth = 0;
      dns_ctx.naddtl = 0;
      dns_ctx.result = 0;

      result = ydns_decode_reply(buf, nread, (void *)&dns_ctx, &my_cb);
      printf("Parse result: %d\n", result);
      if((dns_ctx.nans || (!dns_ctx.is_mdns)) && dns_ctx.result) {
        unsigned char *p = sendbuf;
        ydns_encode_pdu_no_q(&p, dns_ctx.pe - p, question_id,
                0x8400, dns_ctx.nquest, dns_ctx.nans, dns_ctx.nauth, dns_ctx.naddtl);
        perror("before sendto");
        printf("Length: %d\n", (int)(dns_ctx.p - dns_ctx.buf));
        sendto(sock, dns_ctx.buf, (dns_ctx.p - dns_ctx.buf), 0, (struct sockaddr *)&v6_addr, sockaddr_sz);
        perror("sendto");
      }
  }
  
  return 0;
}

