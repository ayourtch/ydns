
#include <stdint.h>

void lookup_name(int sock, char *name);
int parse_dns_reply(unsigned char *buf, int buflen);

#define HOSTNAME_SZ 256

// #define DEBUG
// #define DEBUGX

#ifdef DEBUG 
#define debug(what, ...) printf(__VA_ARGS__)
#else
#define debug(what, ...)
#endif

#ifdef DEBUGX 
#define debugx(what, ...) printf(__VA_ARGS__)
#else
#define debugx(what, ...)
#endif

#define DNS_RC(x) ((x) & 0x0f)

int ydns_encode_request(unsigned char **buf, int buf_sz, int type, char *name, uint16_t id);

/*
 * Called when the header is parsed. Return false, and the processing will stop right there
 */
typedef int ((*ydns_header_func_t)(void *arg, int trunc, int errcode, int qdcount, int ancount, int nscount, int arcount));

/*
 * We parsed one question and want to let you know about it. Don't hang on to domainname - it's
 * going to be reused by the parser as soon as you return from this callback.
 */
typedef int ((*ydns_question_func_t)(void *arg, char *domainname, int type, int class));

/* We got IPv4 address record. Remember - don't hang on to domainname. */

typedef int ((*ydns_a_func_t)(void *arg, char *domainname, uint32_t ttl, uint32_t addr));

/* We got IPv6 address record. IPv6 address is also to copy before you return*/
typedef int ((*ydns_aaaa_func_t)(void *arg, char *domainname, uint32_t ttl, uint8_t *addr));

/* We got CNAME address record. Again - none of the data will persist when you return */
typedef int ((*ydns_cname_func_t)(void *arg, char *domainname, uint32_t ttl, char *cname));


typedef struct decode_callbacks_t {
  ydns_header_func_t             process_header;
  ydns_question_func_t           process_question;
  ydns_a_func_t                  process_a_rr;
  ydns_aaaa_func_t               process_aaaa_rr;
  ydns_cname_func_t              process_cname_rr;
} decode_callbacks_t;


int ydns_decode_reply(unsigned char *buf, int buflen, void *arg, decode_callbacks_t *cb);


