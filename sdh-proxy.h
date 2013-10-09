#ifndef sdhproxyh
#define sdhproxyh


#include <pcap.h>

// Max length of packet to forward
#define SNAP_LEN 1540
// Not sure if interfaces need to be in promisc mode to capture traffic
#define PROMISC 1
// How many ms to wait between packet captures or something
#define TIMEOUT 10

// Size of interfaces array
#define MAX_IFACES 256
#define MAX_PORTS 2048

// Which character to use to separate out comments in config files
#define COMMENT_CHAR '#'



#define ETH_HDR_LENGTH 14
#define UDP_NUM_HEADERS_MASK 0x0F


// List of interfaces. Later on, will make it input these as a file or arg
//char *iface_list[] = {"eth0", "eth1"};;

// To do: put in conditions for things to exito n
extern int do_exit ;

// Toggled with -d on command line. Displays debug info. 
extern int debug ;

  
/**
 * Used to store a list of interfaces and their assocaited data
 **/
typedef struct
{
   pcap_t * pcap_int; // PCAP interface
   char * interface;  // String name of iface
   char pcap_errbuf[PCAP_ERRBUF_SIZE]; // Error buffer for PCAP to use
   bpf_u_int32 address; // IP address 
   bpf_u_int32 netmask; // Netmask 
   long int num_packets;
   long int num_dropped_packets;
} interface_data;


#endif
