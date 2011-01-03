%%{

machine dns;
alphtype unsigned char;

ll = [a-zA-Z];
ldh = [a-zA-Z0-9] | '-';
ld = [a-zA-Z0-9];

x = any;

include "label.rl";

req_id = any any;


response_truncated = 0x82 | 0x83 | 0x86 | 0x87;
response_full = 0x80 | 0x81 | 0x84 | 0x85;
cf_byte1 = response_truncated | response_full;


rc_no_error = (0x00 | 0x20 | 0x80 | 0xc0);
rc_format_error = 0x01 | 0x21 | 0x81 | 0xc1;
rc_server_failure = 0x02 | 0x22 | 0x82 | 0xc2;
rc_name_error = 0x03 | 0x23 | 0x83 | 0xc3;
rc_not_implemented = 0x04 | 0x24 | 0x84 | 0xc4;
rc_refused = 0x05 | 0x25 | 0x85 | 0xc5;
rc_reserved = 0x06 .. 0x0f | 0x26 .. 0x2f | 0x86 .. 0x8f | 0xc6 .. 0xcf;

cf_byte2 = rc_no_error | 
           rc_format_error | 
           rc_server_failure |
           rc_name_error |
           rc_not_implemented |
           rc_refused | 
           rc_reserved;
 
codeflags = cf_byte1 cf_byte2;

uint16 = any @{ savebyte1 = *p; } any @{ printf("RGL: UINT16: %04x\n", (unsigned int)256*savebyte1 + *p); };
uint32 = any any any any;

qdcount = uint16 >{ printf("RGL: Question count\n"); };
ancount = uint16 >{ printf("RGL: Answer count\n"); };
nscount = uint16 >{ printf("RGL: NS count\n"); };
arcount = uint16 >{ printf("RGL: AR count\n"); };

req_header = req_id codeflags qdcount ancount nscount arcount;

# rr = name type(int16) class(int16) ttl(int32) rdlen(int16) rdata(var)

# main := req_header name_segment @{ res = 1; };

# fixme: EDNS0 will be here. Maybe.

nameoffset = 0xc0 .. 0xff any @{ printf("Name from offset\n"); };
end_of_name = nameoffset|0;

dnsname = label* end_of_name @{ printf("RGL: Exiting from lengthy label\n"); };


coded_name = dnsname | 0xc0 .. 0xff any @{ printf("Name from offset\n"); };

encoded_name := coded_name >{ printf("Encoded name, offs: %d, c: '%02x'\n", p-buf, *p); } @{ printf("RGL: Encoded name end\n"); fret; }; 

action call_encoded_name_fhold { fhold; fcall encoded_name; }
action call_encoded_name { fcall encoded_name; }

qname = coded_name;
qtype = uint16 >{ printf("RGL: QType\n"); };
qclass = uint16 >{ printf("RGL: QClass\n"); };

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

ipv4_addr = any any any any;
ipv6_addr = any{16};

# Magic jump
ardata = any @{ savebyte1 = *p; } any @{ savebyte2 = *p; p += (unsigned short)256*savebyte1 + savebyte2; };

check_ardata := ardata @{ fret; };
# check_ardata := any >{ printf("ARDATA\n"); };

action call_ardata { fcall check_ardata; }

cname_len = uint16;
soa_len = uint16;
soa_serial = uint32;
soa_refresh = uint32;
soa_retry = uint32;
soa_expire = uint32;
soa_minimum = uint32;

rr_a = 1 0 1 attl 0 4 @{ printf("Getting IPv4 addr\n"); } ipv4_addr;
rr_ns = 2 0 1 attl cname_len @call_encoded_name; 

rr_soa = 6 0 1 soa_len @call_encoded_name @call_encoded_name 
           soa_serial soa_refresh soa_retry soa_expire soa_minimum;
rr_cname = 5 0 1 attl cname_len @call_encoded_name; 
rr_aaaa = 0x1c 0 1 attl 0 16 ipv6_addr;

rr_some = rr_a | rr_ns | rr_cname | rr_aaaa;

# answer = rr_a | rr_cname | rr_aaaa;
answer = any_dummy @call_encoded_name_fhold 0 rr_some >{ printf("A/AAAA, c: %02x\n", *p); };

answers = answer+ >{ printf("Entering answers\n"); };


main := req_header questions @{ printf("time for some answers\n"); } answers @{ res = 1; };


}%%

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dns.h"

%%write data;

int parse_dns_reply(unsigned char *buf, int buflen) {
  int cs, res = 0;
  int seglen = 0;
  int top = 20;
  int stack[100];
  unsigned char savebyte1;
  unsigned char savebyte2;
  unsigned char *p = (void *) buf;
  unsigned char *pe = p + buflen + 1;
  printf("Parsing reply, length: %d\n", buflen);
  %%write init;
  %%write exec;
  printf("parse result: %d, seglen: %d, pos: %d, c: 0x%02x\n", 
          res, seglen, p-buf, *p);
}

