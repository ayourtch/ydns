void lookup_name(int sock, char *name);
int parse_dns_reply(unsigned char *buf, int buflen);

#ifdef DEBUG 
#define debug(what, ...) printf(__VA_ARGS__)
#else
#define debug(what, ...)
#endif
