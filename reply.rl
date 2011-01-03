#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dns.h"

%%{
machine dns;
alphtype unsigned char;


action response_is_truncated   { (*p | 0x5) == 0x87 }
action response_is_full        { (*p | 0x5) == 0x85 }

cf_byte1 = any when response_is_truncated 
               @{ debug(DNS_PARSE, "Response is truncated\n"); } 
         | any when response_is_full
               @{ debug(DNS_PARSE, "Response is in full\n"); };

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

uint16 = any @{ uint8_acc[0] = *p; } 
             any @{ uint8_acc[1] = *p;
                    uint16_acc = (unsigned short)256*uint8_acc[0] + 
                                                 uint8_acc[1]; };
uint32 = any @{ uint8_acc[0] = *p; }
             any @{ uint8_acc[1] = *p; }
                 any @{ uint8_acc[2] = *p; }
                    any @{ uint8_acc[3] = *p;
                           uint32_acc = (unsigned long)uint8_acc[3] + 
                                        256*(uint8_acc[2] +
                                         256*(uint8_acc[1] +
                                          256*uint8_acc[0])); };

req_id = uint16 >{ debug(DNS_PARSE,"RGL: Request id\n"); };
qdcount = uint16 >{ debug(DNS_PARSE,"RGL: Question count\n"); };
ancount = uint16 >{ debug(DNS_PARSE,"RGL: Answer count\n"); };
nscount = uint16 >{ debug(DNS_PARSE,"RGL: NS count\n"); };
arcount = uint16 >{ debug(DNS_PARSE,"RGL: AR count\n"); };

req_header = req_id codeflags qdcount ancount nscount arcount;

# That beast is tricky.
include "dnsname.rl";

encoded_name = dnsname;

qname = encoded_name >{ debug(DNS_PARSE, "RGL: Question Name\n"); };
qtype = uint16 >{ debug(DNS_PARSE,"RGL: QType\n"); };
qclass = uint16 >{ debug(DNS_PARSE,"RGL: QClass\n"); };

aname = encoded_name >{ debug(DNS_PARSE, "RGL: Answer Name\n"); };
atype = uint16;
aclass = uint16;
attl = uint32;


question = qname qtype qclass;

# only inverse queries can contain multiple questions.
# since we ask always one question, we expect one question
# here.
questions = question;

ipv4_addr = uint32;
ipv6_addr = any @{ acc8pos = 0; uint8_acc[0] = *p; }
            (any @{ uint8_acc[acc8pos++] = *p; }) {15};

# RDATA consumer (not used now, but maybe sometime)

action in_rdata { runlen-- > 0 }
ardata = any @{ uint8_acc[0] = *p; } 
             any @{ runlen = (unsigned short)256*uint8_acc[0] + *p; }
                 (any when in_rdata)**;



cname_len = uint16;
soa_len = uint16;
soa_serial = uint32;
soa_refresh = uint32;
soa_retry = uint32;
soa_expire = uint32;
soa_minimum = uint32;


# Notice that RRs start not with zero - we had to leave
# zero in the expression that calls this one - so
# not to have any ambiguity

rr_a = 1 0 1 attl 0 4 @{ debug(DNS_PARSE,"Getting IPv4 addr\n"); } ipv4_addr;
rr_ns = 2 0 1 attl cname_len encoded_name; 

rr_soa = 6 0 1 soa_len encoded_name encoded_name 
           soa_serial soa_refresh soa_retry soa_expire soa_minimum;
rr_cname = 5 0 1 attl cname_len encoded_name; 
rr_aaaa = 0x1c 0 1 attl 0 16 @{ debug(DNS_PARSE,"Getting IPv6 addr\n"); } ipv6_addr;

rr_whatever = rr_a | rr_ns | rr_soa | rr_cname | rr_aaaa;

answer = aname 0 rr_whatever >{ debug(DNS_PARSE,"RR type: %02x\n", *p); } ;

answers = answer+ >{ debug(DNS_PARSE,"Entering answers\n"); };

main := req_header questions answers >/{ res = 2; } 
                                     @{ res = 1; };


}%%


%%write data;

int parse_dns_reply(unsigned char *buf, int buflen) {
  int cs, res = 0;
  int seglen = 0;
  unsigned char uint8_acc[16];
  unsigned int acc8pos;
  unsigned char *p = (void *) buf;
  unsigned char *sav_p; 
  unsigned char *pe = p + buflen;
  unsigned char *eof = pe;
  int runlen; /* We decrement it. So, better signed than sorry. */
  unsigned short uint16_acc;
  unsigned long uint32_acc;
  int top;
  int stack[10];
  debug(DNS_PARSE,"Parsing reply, length: %d\n", buflen);
  %%write init;
  %%write exec;
  debug(DNS_PARSE,"parse result: %d, seglen: %d, pos: %d, c: 0x%02x\n", 
          res, seglen, p-buf, *p);
  return res;
}

