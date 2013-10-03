

/**
 * timer.c - Run each source IP/dest port pair through the hash table in
 *           this file to ensure that the packet isn't being flooded. 
 */
#include "timer.h"
#include <pcap.h>
#include <time.h>
#include "uthash/uthash.h"
#include <pthread.h>


int pkt_timeout = 1000;
pkt_t *pkthash = NULL;


#define LOOKUP_LENGTH 6

/** 
 * Checks if a given source IP and dest port combo has been broadcast in the
 * last pkt_timeout ms. This is used to prevent a broadcast storm in case of
 * a loop.
 *
 *  IMPORTANT: everything passed in to this function is left in network order.
 *  We don't care what order it's in, as long as it uniquely represents an
 *  IP/port combo. Call ntohs() on the port number if it needs using. 
 *
 * @param address The source IP. 4 bytes. 
 * @param port The destination UDP port. 2 bytes. 
 * @return DROP_PACKET if the packet has been seen recently. SEND_PACKET if it
 *                     has not. 
 **/
int timer_check_packet( const bpf_u_int32 * address, const unsigned short int * port )
{

  char lookup_addr[LOOKUP_LENGTH];  // put address and port in to here
  pkt_t * tmp; // Use this for hash table lookups

  // Form lookup string
  memcpy(&lookup_addr[0], address, 4);
  memcpy(&lookup_addr[0]+sizeof(bpf_u_int32), port, 2);

  HASH_FIND(hh, pkthash, lookup_addr, LOOKUP_LENGTH ,tmp);
  if (tmp)
    printf("Found hash in table.");
  else
  {
    printf("Not found, creating hash in table");
    tmp = ( pkt_t *)malloc(sizeof(pkt_t));
    memcpy(&tmp->ipport,lookup_addr, LOOKUP_LENGTH);
    HASH_ADD(hh, pkthash, ipport, LOOKUP_LENGTH, tmp);
  }



  return SEND_PACKET;
}
