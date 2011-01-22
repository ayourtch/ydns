#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "dns.h"

%%{
machine dns;
alphtype unsigned char;


action response_is_truncated   { (*p | 0x5) == 0x87 }
action response_is_full        { (*p | 0x5) == 0x85 }

cf_byte1 = any when response_is_truncated 
               @{ debug(DNS_PARSE, "Response is truncated\n"); trunc_acc = 1; } 
         | any when response_is_full
               @{ debug(DNS_PARSE, "Response is in full\n"); trunc_acc = 0; };

action rc_is_no_error        { DNS_RC(*p) == 0 }
action rc_is_format_error    { DNS_RC(*p) == 1 }
action rc_is_server_failure  { DNS_RC(*p) == 2 }
action rc_is_name_error      { DNS_RC(*p) == 3 }
action rc_is_not_implemented { DNS_RC(*p) == 4 }
action rc_is_refused         { DNS_RC(*p) == 5 }
action rc_is_reserved        { (DNS_RC(*p) >= 6) && (DNS_RC(*p) <= 0xf) }

cf_byte2 = any when rc_is_no_error | 
           any when rc_is_format_error | 
           any when rc_is_server_failure |
           any when rc_is_name_error |
           any when rc_is_not_implemented |
           any when rc_is_refused | 
           any when rc_is_reserved;
 
codeflags = cf_byte1 cf_byte2;

uint16 = any @{ uint8_acc[0] = *p; } .
             any @{ uint8_acc[1] = *p;
                    uint16_acc = (unsigned short)256*uint8_acc[0] + 
                                                 uint8_acc[1]; 
                  };
uint32 = any @{ uint8_acc[3] = *p; } .
             any @{ uint8_acc[2] = *p; } .
                 any @{ uint8_acc[1] = *p; } .
                    any @{ uint8_acc[0] = *p;
                           uint32_acc = (unsigned long)uint8_acc[3] + 
                                        256*(uint8_acc[2] +
                                         256*(uint8_acc[1] +
                                          256*uint8_acc[0])); };

xid = uint16 >{ debug(DNS_PARSE,"RGL: Request id\n"); };
qdcount = uint16 @{ debug(DNS_PARSE,"RGL: Question count: %d\n", uint16_acc); qdcount_acc = uint16_acc; };
ancount = uint16 @{ debug(DNS_PARSE,"RGL: Answer count: %d\n", uint16_acc); ancount_acc = uint16_acc; };
nscount = uint16 @{ debug(DNS_PARSE,"RGL: NS count: %d\n", uint16_acc); nscount_acc = uint16_acc; };
arcount = uint16 @{ debug(DNS_PARSE,"RGL: AR count: %d\n", uint16_acc); arcount_acc = uint16_acc; };

req_header = xid @{ xid_acc = uint16_acc; } codeflags @{ errcode_acc = DNS_RC(*p); } qdcount ancount nscount arcount;

# That beast is tricky.
include "dnsname.rl";

encoded_name = dnsname;

qname = encoded_name @{ debug(DNS_PARSE, "RGL: Question Name: '%s'\n", hostname_acc); };
qtype = uint16 @{ debug(DNS_PARSE,"RGL: QType %d\n", uint16_acc); qtype_acc = uint16_acc; };
qclass = uint16 @{ debug(DNS_PARSE,"RGL: QClass %d\n", uint16_acc); qclass_acc = uint16_acc; };

aname = encoded_name @{ debug(DNS_PARSE, "RGL: Answer Name: '%s'\n", hostname_acc); };
atype = uint16;
aclass = uint16;
attl = uint32 %{ uint32_attl = ntohl(uint32_acc); };


question = qname qtype qclass @{ cb->process_question(arg, (void*)hostname_acc, qtype_acc, qclass_acc); };

# only inverse queries can contain multiple questions.
# since we ask always one question, we expect one question
# here.
questions = question;

ipv4_addr = uint32;
ipv6_addr = any @{ acc8pos = 0; uint8_acc[acc8pos++] = *p; }
            (any @{ uint8_acc[acc8pos++] = *p; }) {15};

# RDATA consumer (not used now, but maybe sometime)

action in_rdata { runlen-- > 0 }
ardata = any @{ uint8_acc[0] = *p; } 
             any @{ runlen = (unsigned short)256*uint8_acc[0] + *p; }
                 (any when in_rdata)**;



cname_len = uint16;
ns_len = uint16;
soa_len = uint16;
soa_serial = uint32;
soa_refresh = uint32;
soa_retry = uint32;
soa_expire = uint32;
soa_minimum = uint32;


# Notice that RRs start not with zero - we had to leave
# zero in the expression that calls this one - so
# not to have any ambiguity

rr_a = 1 0 1 attl 0 4 @{ debug(DNS_PARSE,"Getting IPv4 addr\n"); } ipv4_addr %{ cb->process_a_rr(arg, (void *)hostname_acc, uint32_attl, uint32_acc); };
rr_ns = 2 0 1 attl cname_len encoded_name;

rr_soa = 6 0 1 attl soa_len encoded_name encoded_name 
           soa_serial soa_refresh soa_retry soa_expire soa_minimum;
rr_cname = 5 0 1 attl @{ memcpy(host_cname_acc, hostname_acc, sizeof(host_cname_acc)); } cname_len encoded_name %{ cb -> process_cname_rr(arg, (void*)host_cname_acc, uint32_attl, (void *) hostname_acc); }; 

rr_aaaa = 0x1c 0 1 attl 0 16 ipv6_addr %{ cb->process_aaaa_rr(arg, (void *)hostname_acc, uint32_attl, uint8_acc); };

rr_whatever = rr_a | rr_ns | rr_soa | rr_cname | rr_aaaa;

answer = aname 
             @{ debug(DNS_PARSE, "Answer Name: '%s'\n", hostname_acc); }
         0 rr_whatever >{ debug(DNS_PARSE,"RR type: %02x, A Name: '%s'\n", *p, hostname_acc); } ;

answers = answer+ >{ debug(DNS_PARSE,"Entering answers\n"); };

main := req_header @{ cb->process_header(arg, xid_acc, trunc_acc, errcode_acc, qdcount_acc, ancount_acc, nscount_acc, arcount_acc); } 
                                     questions answers >/{ res = 2; } 
                                     @{ res = 1; };


}%%


%%write data;

int ydns_decode_reply(unsigned char *buf, int buflen, void *arg, decode_callbacks_t *cb) {
  int cs, res = 0;
  int seglen = 0;
  unsigned char uint8_acc[16];
  unsigned int acc8pos;
  unsigned char hostname_acc[HOSTNAME_SZ];
  unsigned int acchpos;
  unsigned char host_cname_acc[HOSTNAME_SZ];
  unsigned char *p = (void *) buf;
  unsigned char *sav_p; 
  unsigned char *pe = p + buflen;
  unsigned char *eof = pe;
  int max_label_indirection = 10;
  int label_indirection;
  int runlen; /* We decrement it. So, better signed than sorry. */
  unsigned short uint16_acc;
  unsigned long uint32_acc;
  unsigned long uint32_attl;
  int xid_acc;
  int qdcount_acc, ancount_acc, nscount_acc, arcount_acc, trunc_acc, errcode_acc;
  int qtype_acc, qclass_acc;
  int top;
  int stack[10];
  
  debug(DNS_PARSE,"Parsing reply, length: %d\n", buflen);
  %%write init;
  %%write exec;
  debug(DNS_PARSE,"parse result: %d, seglen: %d, pos: %d, c: 0x%02x\n", 
          res, seglen, p-buf, *p);
  return res;
}

