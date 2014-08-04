
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


enum {
  DNS_T_A = 1,
  DNS_T_NS,
  DNS_T_CNAME = 5,
  DNS_T_SOA,
  DNS_T_PTR = 12,
  DNS_T_MX = 15,
  DNS_T_TXT = 16,
  DNS_T_AAAA = 28,
  DNS_T_X
};

/*
 * A simple API to encode a request: pass the type/name, id, the buffer size 
 * and the pointer to the pointer to the buffer.
 * The *buf will be modified to point to the first byte past end of the buffer upon success (return 1);
 */
int ydns_encode_request(unsigned char **buf, int buf_sz, int type, char *name, uint16_t id);

/*
 * A more generic version with more arguments but the same logic as above. 
 */
int ydns_encode_pdu(unsigned char **buf, int buf_sz,
                uint16_t qtype,
                char *name,
                uint16_t id,
                uint16_t opcode_flags,
                uint16_t qdcount,
                uint16_t ancount,
                uint16_t nscount,
                uint16_t arcount,
                uint16_t qclass); 

/* RR encoding */
int ydns_encode_rr_start(unsigned char **buf, int buf_sz,
                char *name,
                uint16_t type,
                uint16_t class,
                uint32_t ttl);

int ydns_encode_rr_data(unsigned char **buf, int buf_sz,
                        void *src, int len);

int ydns_encode_rr_soa(unsigned char **buf, int buf_sz,
                        char *nsname,
                        char *admin,
                        uint32_t serial,
                        uint32_t refresh,
                        uint32_t retry,
                        uint32_t expire,
                        uint32_t min_ttl); 

/*
 * Called when the header is parsed. Return false, and the processing will stop right there
 */
typedef int ((*ydns_header_func_t)(void *arg, int req_id, int flags, int trunc, int errcode, int qdcount, int ancount, int nscount, int arcount));

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

/* We got PTR address record. Again - none of the data will persist when you return */
typedef int ((*ydns_ptr_func_t)(void *arg, char *domainname, uint32_t ttl, char *cname));

typedef struct decode_callbacks_t {
  ydns_header_func_t             process_header;
  ydns_question_func_t           process_question;
  ydns_a_func_t                  process_a_rr;
  ydns_aaaa_func_t               process_aaaa_rr;
  ydns_cname_func_t              process_cname_rr;
  ydns_ptr_func_t                process_ptr_rr;
} decode_callbacks_t;


int ydns_decode_reply(unsigned char *buf, int buflen, void *arg, decode_callbacks_t *cb);


