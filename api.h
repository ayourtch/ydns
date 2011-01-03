#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

/*
 * Initialize the needed data structures.
 * Allocating (or using static data) is the responsibility
 * of the caller. 
 */

typedef void ydns_t;

enum { YDNS_OK, YDNS_NO_NAME, YDNS_SERVER_ERROR };

int ydns_init(ydns_t *ydns_root);

/* 
 * Send howmuch bytes of whattosend, also the arg from the original lookup call also passed,
 * Also you get a chance to record a per-request verification value, up to sigsize bytes.
 * This one can be matched later on during the processing with your received verification value.
 * An example of that could be e.g. the host you are sending to, and the local port you are sending
 * from. Since we don't do sockets we can not know that. Return the number of bytes actually sent.
 */ 
  
typedef int ((*ydns_send_func_t)(void *whattosend, int howmuch, void *arg, char *sigbuf, int sigsize));

/*
 * Pass the result - for the request that passed arg.
 * result code is one of the enum values above.
 * If the result is ok - then ai points to the chain of addrinfo structures similar to getaddrinfo.
 * Unlike the getaddrinfo - you do not have to free it if you do not want. Just return true and
 * the library will take care of this for you. If you need those, on the other hand - 
 * return 0 (false, i am not done with that addresses) - and then freeing them becomes
 * your responsibilty (TBD: how to free)
 */
 
typedef int ((*ydns_done_func_t)(void *arg, int resultcode, struct addrinfo *ai));

/* 
 * Initiate a lookup of a hostname - the full CNAME/A/AAAA business.
 * send_func callback will be called to send the data.
 *
 * arg will be passed to done_func whenever there is a result (or error).
 *
 */

void ydns_lookup(ydns_t *ydns_root, char *hostname, ydns_send_func_t send_func,
                             ydns_done_func_t done_func, void *arg);

/* 
 * You have got some raw data that you'd want to process and dispatch.
 * This function is for you.
 * Give it the data and its length - or no data at all, then it would not
 * process anything. 
 * But give also the send_func - so it does the retransmits if needed.
 * No send_func passed - no retransmits. The requests will fail faster.
 * 
 * The return result is how many microseconds later this function
 * would like to be called again to handle the pending retransmits.
 *
 */

int ydns_process(ydns_t *ydns_root, char *data, int datalen, 
                      char *sigbuf, int sigsize,
                      ydns_send_func_t send_func);


