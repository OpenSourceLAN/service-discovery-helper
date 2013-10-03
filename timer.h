#ifndef TIMER_H
#define TIMER_H

#include <pcap.h>
#include "uthash/uthash.h"
#include <pthread.h>

#define DROP_PACKET 1
#define SEND_PACKET 0

// Number of ms between repeats of an identical src ip/dest port broadcast
extern int pkt_timeout;

typedef struct {
  unsigned long long ipport;
  time_t lasthit;
  UT_hash_handle hh;
} pkt_t;

pthread_rwlock_t timer_lock;


int timer_check_packet( const bpf_u_int32 * address, const unsigned short int * port );
#endif
