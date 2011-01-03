#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dns.h"

%%{
machine dns;
alphtype unsigned char;

# The original DNS name types
# Starts only with a letter
letter_only = [a-zA-Z];
# Then can have maybe some letters numbers and dashes
letter_digit_dash = [a-zA-Z0-9] | '-';
# and ends with a letter or digit
letter_or_digit = [a-zA-Z0-9];


action in_label { runlen-- > 0 }

label_itself =
      1 @{ seglen = 1; runlen = 0; } letter_only |
      2 @{ seglen = 2; runlen = 0; } letter_only letter_or_digit |
      3..63 @{ runlen = *p-2; seglen = *p; } 
            letter_only (letter_digit_dash when in_label)+ letter_or_digit;

label = 
  1..63 @{ debug(LABEL_DEBUG, "LABEL: %d, ofs: %d\n", *p, p-buf); fhold; } 
        label_itself;



response_truncated = 0x82 | 0x83 | 0x86 | 0x87;
response_full = 0x80 | 0x81 | 0x84 | 0x85;
cf_byte1 = response_truncated | response_full;

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
             any @{ uint16_acc = (unsigned short)256*uint8_acc[0] + *p; };
uint32 = any @{ uint8_acc[0] = *p; }
             any @{ uint8_acc[1] = *p; }
                 any @{ uint8_acc[2] = *p; }
                    any @{ uint8_acc[3] = *p; };

req_id = uint16 >{ debug(DNS_PARSE,"RGL: Request id\n"); };
qdcount = uint16 >{ debug(DNS_PARSE,"RGL: Question count\n"); };
ancount = uint16 >{ debug(DNS_PARSE,"RGL: Answer count\n"); };
nscount = uint16 >{ debug(DNS_PARSE,"RGL: NS count\n"); };
arcount = uint16 >{ debug(DNS_PARSE,"RGL: AR count\n"); };

req_header = req_id codeflags qdcount ancount nscount arcount;

# fixme: EDNS0 will be here. Maybe.
nameoffset = 0xc0 .. 0xff any @{ debug(DNS_PARSE,"Name from offset\n"); };
end_of_name = nameoffset|0;

dnsname = (end_of_name | label+ end_of_name) @{ debug(DNS_PARSE,"RGL: Exiting from lengthy label\n"); };


coded_name = dnsname | 0xc0 .. 0xff any @{ debug(DNS_PARSE,"Name from offset\n"); };

encoded_name := coded_name >{ debug(DNS_PARSE,"Encoded name, offs: %d, c: '%02x'\n", p-buf, *p); } @{ debug(DNS_PARSE,"RGL: Encoded name end\n"); fret; }; 

action call_encoded_name_fhold { fhold; fcall encoded_name; }
action call_encoded_name { fcall encoded_name; }

qname = coded_name;
qtype = uint16 >{ debug(DNS_PARSE,"RGL: QType\n"); };
qclass = uint16 >{ debug(DNS_PARSE,"RGL: QClass\n"); };

aname = coded_name;
atype = uint16;
aclass = uint16;
attl = uint32;


any_dummy = any;
question = any_dummy @call_encoded_name_fhold qtype qclass;

# only inverse queries can contain multiple questions.
# since we ask always one question, we expect one question
# here.
questions = question;

ipv4_addr = uint32;
ipv6_addr = any {16};

action in_rdata { runlen-- > 0 }
# Magic jump
ardata = any @{ uint8_acc[0] = *p; } 
             any @{ runlen = (unsigned short)256*uint8_acc[0] + *p; }
                 (any when in_rdata)**;

check_ardata := ardata @{ fret; };
# check_ardata := any >{ debug(DNS_PARSE,"ARDATA\n"); };

action call_ardata { fcall check_ardata; }

cname_len = uint16;
soa_len = uint16;
soa_serial = uint32;
soa_refresh = uint32;
soa_retry = uint32;
soa_expire = uint32;
soa_minimum = uint32;

rr_a = 1 0 1 attl 0 4 @{ debug(DNS_PARSE,"Getting IPv4 addr\n"); } ipv4_addr;
rr_ns = 2 0 1 attl cname_len @call_encoded_name; 

rr_soa = 6 0 1 soa_len @call_encoded_name @call_encoded_name 
           soa_serial soa_refresh soa_retry soa_expire soa_minimum;
rr_cname = 5 0 1 attl cname_len @call_encoded_name; 
rr_aaaa = 0x1c 0 1 attl 0 16 @{ debug(DNS_PARSE,"Getting IPv6 addr\n"); } ipv6_addr;

rr_whatever = rr_a | rr_ns | rr_soa | rr_cname | rr_aaaa;

answer = any_dummy @call_encoded_name_fhold 0 rr_whatever >{ debug(DNS_PARSE,"RR type: %02x\n", *p); } ;

answers = answer+ >{ debug(DNS_PARSE,"Entering answers\n"); };


main := req_header questions @{ debug(DNS_PARSE,"time for some answers\n"); } answers @{ res = 1; };


}%%


%%write data;

int parse_dns_reply(unsigned char *buf, int buflen) {
  int cs, res = 0;
  int seglen = 0;
  int top = 20;
  int stack[100];
  unsigned char uint8_acc[16];
  unsigned char *p = (void *) buf;
  unsigned char *pe = p + buflen + 1;
  unsigned short runlen;
  unsigned short uint16_acc;
  debug(DNS_PARSE,"Parsing reply, length: %d\n", buflen);
  %%write init;
  %%write exec;
  debug(DNS_PARSE,"parse result: %d, seglen: %d, pos: %d, c: 0x%02x\n", 
          res, seglen, p-buf, *p);
  return res;
}

