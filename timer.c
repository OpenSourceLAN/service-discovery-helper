

/**
 * timer.c - Run each source IP/dest port pair through the hash table in
 *           this file to ensure that the packet isn't being flooded. 
 */
#include "timer.h"
#include <pcap.h>
#include <time.h>
#include "uthash/uthash.h"
#include <pthread.h>

int timer_enabled = 1;
int pkt_timeout_s = 1;
int pkt_timeout_us = 0;
pkt_t *pkthash = NULL;

pthread_rwlock_t timer_lock;

#define LOOKUP_LENGTH 6


/** 
 * Compare a packet's last seen time with a given now time, and see if the
 * difference is > or < than the pkt_timeout_(u)s values
 *
 * @param oldtime The 'old' time the packet was last seen
 * @param now What is considered to be 'now'
 * @return DROP_PACKET or SEND_PACKET accordingly
 * */

int timer_drop_packet(struct timeval *  oldtime, struct timeval * now)
{
  if (oldtime->tv_sec + pkt_timeout_s < now->tv_sec)
  {
    return SEND_PACKET;
  }
  else if ( oldtime->tv_sec + pkt_timeout_s == now->tv_sec)
  {
    if ( oldtime->tv_usec + pkt_timeout_us < now->tv_usec)
      return SEND_PACKET;
    else
      return DROP_PACKET;
  }
  return DROP_PACKET;
}


/**
 * Initialise the r/w lock for the hash table
 * */
void timer_init()
{

  pthread_rwlock_init(&timer_lock,NULL);
}

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
  
  struct timeval now;
  gettimeofday(&now, NULL);

  // Check if the  packet has been recently sent
  pthread_rwlock_rdlock(&timer_lock);
  HASH_FIND(hh, pkthash, lookup_addr, LOOKUP_LENGTH ,tmp);
  pthread_rwlock_unlock(&timer_lock);

  if (tmp)
  {
    // Found a match
    if ( timer_drop_packet(&(tmp->lasthit), &now) == SEND_PACKET)
    {
      // Update time 
      memcpy(&(tmp->lasthit), &now, sizeof(struct timeval));
      return SEND_PACKET;
    }
    else
    {
      // Return drop packet - don't update time
      return DROP_PACKET;
    }
    
  }
  else
  {
    tmp = ( pkt_t *)malloc(sizeof(pkt_t));
    memcpy(&tmp->ipport,lookup_addr, LOOKUP_LENGTH);
    memcpy(&(tmp->lasthit), &now, sizeof(struct timeval));

    pthread_rwlock_wrlock(&timer_lock);
    HASH_ADD(hh, pkthash, ipport, LOOKUP_LENGTH, tmp);
    pthread_rwlock_unlock(&timer_lock);
  }



  return SEND_PACKET;
}
