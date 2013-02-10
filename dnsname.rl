#include "dns.h"

%%{

machine dns;
alphtype unsigned char;


action hostname_char_s {
    debugx(LABEL_DEBUG, "letter(sta): '%c'(0x%02x), run: %d, pos: %ld\n", *p, *p, runlen, p-buf);
    if(acchpos < HOSTNAME_SZ) { hostname_acc[acchpos++] = *p; } 
    else { return 0; }
}
action hostname_char_c {
    debugx(LABEL_DEBUG, "letter(cnt): '%c'(0x%02x), run: %d, pos: %ld\n", *p, *p, runlen, p-buf);
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
    debugx(DNS_PARSE, "LABEL: %d\n", seglen); 
}

label_itself =
      1..63 when not_in_label @label_start
            letter_or_digit @hostname_char_s
            (
              (dash when in_label | letter_or_digit) @hostname_char_c
                 @{ runlen--; } 
            )**;

label =  label_itself %check_label_len;

labels := label* $!{fhold;fret;};

compressed_label = 0xc0 .. 0xff @{ uint8_acc[0] = *p & 0x3f; } . any;  

u_labels := 1..63 @{ fhold; } .
            (label+ .
            compressed_label? @{ 
                        uint16_acc = 256*uint8_acc[0] + *p;
                        debugx(DNS_PARSE, "Second Jump p from %ld to %d (content: 0x%02x)\n", 
                        p - buf, uint16_acc, *p);
                        p = buf + uint16_acc -1;
			if(++label_indirection > max_label_indirection) {
                          debugx(DNS_PARSE, "Too much of indirection while unpacking label\n");
                          return 0;
                        }
                        fgoto u_labels;
                    })

                    $!{fhold; 
                      debugx(DNS_PARSE, "Returning from %ld to %ld\n", 
                            p-buf, sav_p-buf); 
                      p = sav_p; 
                      fret;};

action uncompress_name {
  uint16_acc = 256*uint8_acc[0] + *p;
  sav_p = p;
  if (p-buf > uint16_acc) {
    p = buf + uint16_acc -1;
    debugx(DNS_PARSE, "Jump p from %ld to %ld (content: 0x%02x)\n", 
          sav_p - buf, p-buf, *p);
    fcall u_labels;
  } else {
    debug(DNS_PARSE, "Not jumping ahead while decompressing. Sorry.\n");
    return 0;
  }
}

name_from_offset = 0xc0 .. 0xff @{ uint8_acc[0] = *p & 0x3f; } .
                   any @uncompress_name;
end_of_name = name_from_offset | 0;

dnsname = any @{ fhold; runlen = -1; acchpos = 0; label_indirection = 0; fcall labels; } .
          end_of_name @{ debug(DNS_PARSE,"RGL: Exiting dnsname\n"); };


}%%
