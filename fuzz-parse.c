#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "dns.h"

decode_callbacks_t cb = { 
};

void breakpoint () {
}

int main(int argc, char *argv[]) {
  int minsz = argc > 1 ? atoi(argv[1]) : 0 ;
  int maxsz = argc > 2 ? atoi(argv[2]) : 3000;
  int num_iter = argc > 3 ? atoi(argv[3]) : 50000;
  int seed = argc > 4 ? atoi(argv[4]) : 1;
  int stop_len = argc > 5 ? atoi(argv[5]) : 0;
  int stop_iter = argc > 6 ? atoi(argv[6]) : 0;
  unsigned char *buf;
  int len, iter;
  int ret;
  
  buf = malloc(maxsz);
  assert(buf);
  srand(seed);

  for(len = minsz; len <= maxsz; len++) {
    for(iter = 0; iter < num_iter; iter++) {
      int i;
      for(i = 0; i < len; i++) {
        buf[i] = rand();
      }
      printf("\033[1Alen: %d, iter: %d    \n", len, iter);
      if((len == stop_len) && (iter == stop_iter)) breakpoint();
      ret = ydns_decode_reply(buf, len, (void *)0xdeadbeef, &cb);
    }
  }
  
  
  return 0;   
}
