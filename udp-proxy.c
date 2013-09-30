/*
 * Game Server Discovery Helper
 * (or any UDP service discovery helper)
 *
 * (c) Chris "SirSquidness" Holman, October 2013
 *
 * Licensed under the .... license.
 *
 * Forwards UDP broadcasts on given ports out other interfaces on the system. 
 * Useful for discovering game (or other) servers on other VLANs. Makes sure 
 * not to send a broadcast back out the same interface. 
 *
 * Usage: 
 *
 *
 * Requires root
 * Requires libpcap and the libpcap headers (libpcap-dev) to be installed.
 * 
 * Compile using:
 * gcc -o udp-proxy udp-proxy.c -lpcap -lpthread
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <pthread.h>

#define OUTPUT_INT "eth1"
#define INPUT_INT "eth0"
#define SNAP_LEN 1540
#define PROMISC 1
#define TIMEOUT 10

typedef struct
{
   pcap_t * pcap_int;
   char * interface;
   char pcap_errbuf[PCAP_ERRBUF_SIZE];
} interface_data;



char filter[] = "udp and port 27015";

pcap_t* int_in;
pcap_t* int_out;

/**
 * Given a source interface name and a packet, flood that packet to every other
 * interface
 * 
 * @param args Deprecated. Will remove this soon. 
 * @param header The PCAP packet header (contains length of packet)
 * @param packet The packet to be flooded
 *
 **/
void flood_packet( u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  printf("Packet length %d", header->len);
  pcap_inject(int_out, packet, header->len);
}

/** 
 * Starts listening for incoming broadcasts, and sends them to be dealt with
 * Thread entry point
 *
 * @param args: The struct contains the name of the interface and the pcap_t pointer
 *
 **/
void start_listening(const interface_data * args)
{
//  while (1)
  {
    // Do things here
  }
}

/** 
 * Initialises a PCAP interface and applies the filters we need
 *
 * @param interface: The name of the interface to use
 **/
pcap_t * init_pcap_int ( const char * interface, char * errbuf)
{
  pcap_t * ret;
  struct bpf_program  fp;
  errbuf = "\0";
    printf("Opening PCAP interface for %s\n", interface);
  ret = pcap_open_live(interface, SNAP_LEN, PROMISC, TIMEOUT, errbuf);

  if (ret == NULL)
  {
    fprintf(stderr, "Error opening interface for listening");
    return NULL;
  }

  if ( pcap_compile(ret, &fp, filter, 0, 0 ) == -1 ) {
      fprintf(stderr, "Error compiling filter");
      return NULL;
  }

  if (pcap_setfilter(ret, &fp) == -1 ) {
    fprintf(stderr, "Error setting filter");
    return NULL;
  }

  if (pcap_setdirection(ret, PCAP_D_IN) == -1) {
    fprintf(stderr, "Error setting direction");
    return NULL;
  }
  return ret;
}

int main()
{
  pthread_t * threads;
  
  int i;

  // This will come from argc/argv later
  char *iface_list[] = {"eth0", "eth1"};
  int num_ifaces = sizeof(iface_list)/sizeof(iface_list[0]);
  interface_data *iface_data;

  iface_data = malloc( num_ifaces * sizeof(interface_data) );
  threads = malloc (num_ifaces * sizeof(pthread_t));
  

  // Create all of the interface listeners
  for (i = 0; i < num_ifaces; i++)
  {
    iface_data[i].interface =   iface_list[i];
    iface_data[i].pcap_int = init_pcap_int(iface_list[i], iface_data[i].pcap_errbuf );
    if (iface_data[i].pcap_int == NULL)
    {
      fprintf(stderr, "Couldn't create a listener for all interfaces. Exiting.");
      return -1;
    }
  }

  // Once everything is created, then spawn the processing threads
  for (i = 0; i< num_ifaces; i++)
  {
    pthread_create(&threads[i], NULL, start_listening, &iface_data[i]);
  }
  
  for (i = 0; i< num_ifaces; i++)
  {
    pthread_join(threads[i], NULL);
  }

  return 0;
}
