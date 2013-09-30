/*
 * Service Discovery Helper
 * For game server discovery across VLANs, and similar applications
 *
 * (c) Chris "SirSquidness" Holman, October 2013
 * Licensed under the MIT License license.
 * See LICENSE for more details
 *
 * Forwards UDP broadcasts on given ports out other interfaces on the system. 
 * Useful for discovering game (or other) servers on other VLANs. Makes sure 
 * not to send a broadcast back out the same interface. 
 *
 * Usage: 
 *  sudo ./sdh-proxy
 *
 * Currently requires configuration to be hard coded. I'll fix that soon. 
 * (honest!). Edit the iface_list array to contain all interfaces you use.
 * Edit the filter_string example to include all UDP port numbers. 
 *
 * Requires root
 * Requires libpcap and the libpcap headers (libpcap-dev) to be installed.
 * 
 * Compile using:
 * gcc -g -std=gnu99 -o sdh-proxy sdh-proxy.c -lpcap -lpthread
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <pthread.h>

// Max length of packet to forward
#define SNAP_LEN 1540
// Not sure if interfaces need to be in promisc mode to capture traffic
#define PROMISC 1
// How many ms to wait between packet captures or something
#define TIMEOUT 10

/**
 * Stored in the inferface_data array, contains the name, pcap_t and 
 * error string for each interface
 **/
typedef struct
{
   pcap_t * pcap_int;
   char * interface;
   char pcap_errbuf[PCAP_ERRBUF_SIZE];
} interface_data;

// List of interfaces. Later on, will make it input these as a file or arg
char *iface_list[] = {"eth0", "eth1"};;
int num_ifaces;

interface_data *iface_data;

// Auto generate this later. This defines which ports will be forwarded
char filter[] = "udp and ( port 27015 or port 27016) ";

int do_exit = 0;
int debug = 1;

/**
 * Given a source interface name and a packet, flood that packet to every other
 * interface
 * 
 * @param args Deprecated. Will remove this soon. 
 * @param header The PCAP packet header (contains length of packet)
 * @param packet The packet to be flooded
 *
 **/
void flood_packet( interface_data *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  int i;
  printf("Packet length %d", header->len);
  for (i = 0; i < num_ifaces; i++)
  {
    if (strcmp(iface_list[i], args->interface) != 0)
    {
      pcap_inject(iface_data[i].pcap_int, packet, header->len);

    }
  }
}

/** 
 * Starts listening for incoming broadcasts, and sends them to be dealt with
 * Thread entry point
 *
 * @param args: The struct contains the name of the interface and the pcap_t pointer
 *
 **/
void start_listening(const interface_data * iface_data)
{
  while (1)
  {
    if (do_exit) break;
    
    pcap_loop(iface_data->pcap_int, 2, flood_packet, iface_data);
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

  // Create the pcap_t
  ret = pcap_open_live(interface, SNAP_LEN, PROMISC, TIMEOUT, errbuf);
  if (ret == NULL)
  {
    fprintf(stderr, "Error opening interface for listening");
    return NULL;
  }

  // Compile the filter for this interface
  if ( pcap_compile(ret, &fp, filter, 0, 0 ) == -1 ) {
      fprintf(stderr, "Error compiling filter");
      return NULL;
  }

  // Apply the filter
  if (pcap_setfilter(ret, &fp) == -1 ) {
    fprintf(stderr, "Error setting filter");
    return NULL;
  }

  // Only listen to input traffic
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
  //iface_list = {"eth0", "eth1"};
  num_ifaces = sizeof(iface_list)/sizeof(iface_list[0]);
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

  // Once all pcap_ts are created, then spawn the processing threads
  for (i = 0; i< num_ifaces; i++)
  {
    pthread_create(&threads[i], NULL, start_listening, &iface_data[i]);
  }
  
  // Wait for all threads to finish before exiting
  for (i = 0; i< num_ifaces; i++)
  {
    pthread_join(threads[i], NULL);
  }

  return 0;
}
