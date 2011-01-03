%%{

machine dns;

action debug_label_s {
    debug(LABEL_DEBUG, "letter(s): '%c'(0x%02x), run: %d\n", *p, *p, runlen);
}
action debug_label_m {
    debug(LABEL_DEBUG, "letter(m): '%c'(0x%02x), run: %d\n", *p, *p, runlen);
}
action debug_label_e {
    debug(LABEL_DEBUG, "letter(e): '%c'(0x%02x), run: %d\n", *p, *p, runlen);
}


letter_only = [a-zA-Z];
# Then can have maybe some letters numbers and dashes
dash = '-';
# and ends with a letter or digit
letter_or_digit = [a-zA-Z0-9];


action in_label { runlen > 0 }
action not_in_label { runlen <= 0 }
action check_label_len { 
    if(runlen >0) { 
      debug(DNS_PARSE, "Label FSM exit too early, left runlen: %d\n", runlen);
       return 0; 
    } 
}

label_itself =
      1..63 @{ runlen = *p-2; seglen = *p; 
                  debug(DNS_PARSE, "LABEL: %d\n", *p); }
            letter_only @debug_label_s
            (
              (dash when in_label | letter_or_digit) %debug_label_e
                 @{ runlen--; } 
            )**;

label = label_itself @check_label_len;

name_from_offset = 0xc0 .. 0xff any @{ debug(DNS_PARSE,"Name from offset\n"); };
end_of_name = name_from_offset | 0;

dnsname = label* end_of_name @{ debug(DNS_PARSE,"RGL: Exiting dnsname\n"); };

}%%
