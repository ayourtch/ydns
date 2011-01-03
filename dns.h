void lookup_name(int sock, char *name);
int parse_dns_reply(unsigned char *buf, int buflen);

#define DEBUG
#ifdef DEBUG 
#define debug(what, ...) printf(__VA_ARGS__)
#else
#define debug(what, ...)
#endif

#define DNS_RC(x) ((x) & 0x0f)
