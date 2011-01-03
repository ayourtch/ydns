#include "dns.h"

%%{

machine dns;

action hostname_char_s {
    // debug(LABEL_DEBUG, "letter(sta): '%c'(0x%02x), run: %d\n", *p, *p, runlen);
    if(acchpos < HOSTNAME_SZ) { hostname_acc[acchpos++] = *p; } 
    else { return 0; }
}
action hostname_char_c {
    // debug(LABEL_DEBUG, "letter(cnt): '%c'(0x%02x), run: %d\n", *p, *p, runlen);
    if(acchpos < HOSTNAME_SZ) { hostname_acc[acchpos++] = *p; }
    else { return 0; }
}

letter_only = [a-zA-Z];
# Then can have maybe some letters numbers and dashes
dash = '-';
# and ends with a letter or digit
letter_or_digit = [a-zA-Z0-9];


action in_label { runlen > 0 }
action not_in_label { runlen < 0 }
action check_label_len { 
    if(runlen >0) { 
       debug(DNS_PARSE, "Label FSM exit too early, left runlen: %d\n", runlen);
       return 0; 
    } 
}

action label_start {
    runlen = *p-2; seglen = *p; 
    if (p + seglen >= pe) {
      /* We're going to fall past the buffer. Bail. */
      debug(DNS_PARSE, "Label stretches past buffer\n");
      return 0;
    }
    if (acchpos > 0) {
      hostname_acc[acchpos++] = '.'; 
      /* this is not the first label, so put the dot inbetween. */ 
    }
    if(acchpos + *p < HOSTNAME_SZ) {
      hostname_acc[acchpos + *p] = 0; 
    } else {
      debug(DNS_PARSE, "Hostname too long");
      return 0;
    }
    // debug(DNS_PARSE, "LABEL: %d\n", seglen); 
}

label_itself =
      1..63 when not_in_label @label_start
            letter_only @hostname_char_s
            (
              (dash when in_label | letter_or_digit) @hostname_char_c
                 @{ runlen--; } 
            )**;

label =  label_itself %check_label_len;

labels := label* $!{fhold;fret;};

u_labels := 1..63 @{ fhold; } 
            label* $!{fhold; 
                      debug(DNS_PARSE, "Returning from %d to %d\n", 
                            p-buf, sav_p-buf); 
                      p = sav_p; 
                      fret;};

action uncompress_name {
  uint16_acc = 256*uint8_acc[0] + *p;
  sav_p = p;
  if (p-buf > uint16_acc) {
    p = buf + uint16_acc -1;
    debug(DNS_PARSE, "Jump p from %d to %d (content: 0x%02x)\n", 
          sav_p - buf, p-buf, *p);
    fcall u_labels;
  } else {
    debug(DNS_PARSE, "Not jumping ahead while decompressing. Sorry.\n");
    return 0;
  }
}

name_from_offset = 0xc0 .. 0xff @{ uint8_acc[0] = *p & 0x3f; }
                   any @uncompress_name;
end_of_name = name_from_offset | 0;

dnsname = any @{ fhold; runlen = -1; acchpos = 0; fcall labels; } 
          end_of_name @{ debug(DNS_PARSE,"RGL: Exiting dnsname\n"); };


}%%
