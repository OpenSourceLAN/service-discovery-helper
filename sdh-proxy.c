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
#include <ctype.h>

// For getuid() and geteuid()
#include <unistd.h>
#include <sys/types.h>

// Max length of packet to forward
#define SNAP_LEN 1540
// Not sure if interfaces need to be in promisc mode to capture traffic
#define PROMISC 1
// How many ms to wait between packet captures or something
#define TIMEOUT 10

// Size of interfaces array
#define MAX_IFACES 256
#define MAX_PORTS 2048

#define COMMENT_CHAR '#'
/**
 * Stored in the inferface_data array, contains the name, pcap_t and 
 * error string for each interface
 **/
typedef struct
{
   pcap_t * pcap_int;
   char * interface;
   char pcap_errbuf[PCAP_ERRBUF_SIZE];
   bpf_u_int32 address;
   bpf_u_int32 netmask;
} interface_data;

// List of interfaces. Later on, will make it input these as a file or arg
//char *iface_list[] = {"eth0", "eth1"};;
char * iface_list[MAX_IFACES];
int num_ifaces = 0;

// The list of ports from the input files get read in to this before 
// the filter string is made. 
char * port_list[MAX_PORTS];
int num_ports = 0;

interface_data *iface_data;

// Auto generate this later. This defines which ports will be forwarded
char filter[] = "ether dst ff:ff:ff:ff:ff:ff and udp and \
( port 27015 or port 27016 or port 1947 or port 3979 or \
  port 10777 or port 44400 or portrange 2350-2360 or port 2302   \
 or port 6112  or port 50001 or port 23757    \
  ) ";

int do_exit = 0;
int debug = 1;
int do_network_rewrite = 0; // Rewrite IP broadcast address for the new
                            // network interface
  
/**
  * Calculate checksum for IP packet.
  * Taken from http://stackoverflow.com/a/7010971
  * No idea what the license for it is; public domain? Hopefully!
  *
  * @param ptr Pointer to the frame contents
  * @param nbytes How many bytes long the frame is
  * @return The checksum.
  */
unsigned short in_cksum(unsigned short *ptr, int nbytes) {

    register long sum; /* assumes long == 32 bits */
    u_short oddbyte;
    register u_short answer; /* assumes u_short == 16 bits */
    /*
     * the algorithm is simple, using a 32-bit accumulator (sum),
     * we add sequential 16-bit words to it, and at the end, fold back
     * all the carry bits from the top 16 bits into the lower 16 bits.
     */
    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nbytes == 1) {
        oddbyte = 0; /* make sure top half is zero */
        *((u_char *) &oddbyte) = *(u_char *) ptr; /* one byte only */
        sum += oddbyte;
    }

    /*
     * Add back carry outs from top 16 bits to low 16 bits.
     */
    sum = (sum >> 16) + (sum & 0xffff); /* add high-16 to low-16 */
    sum += (sum >> 16); /* add carry */
    answer = ~sum; /* ones-complement, then truncate to 16 bits */
    return (answer);
}


/**
 * Given a source interface name and a packet, flood that packet to every other
 * interface
 * 
 * @param args 
 * @param header The PCAP packet header (contains length of packet)
 * @param packet The packet to be flooded
 *
 **/
void flood_packet( u_char *source_iface, const struct pcap_pkthdr *header, const u_char *packet)
{
  int i;
  u_char * sendpacket;
  sendpacket = malloc(header->len);
  memcpy(sendpacket, packet, header->len);

  // Optionally rewrite the IP layer broadcast address to suit the new subnet
  if ( do_network_rewrite > 0)
  {
    // This resets the checksum to 0
    sendpacket[24] = 0x00;
    sendpacket[25] = 0x00;
    // Reset broadcast address to 255.255.255.255
    for (i = 30; i<34; i++)
      sendpacket[i] = 0xFF;
    // This isn't actually the packet checksum. One needs to create a pseudo 
    // header first; I'll do that later. 
    //printf("Packet checksum: %x\n", in_cksum((unsigned short *)sendpacket, header->len));
  }

  printf("Packet length %d\n", header->len);
  for (i = 0; i < num_ifaces; i++)
  {
    if (strcmp(iface_list[i], (const char *)source_iface) != 0)
    {
      pcap_inject(iface_data[i].pcap_int, sendpacket, header->len);

    }
  }

  // we only malloc() this if we're modifying the frame
  //if (do_network_rewrite>0)   // malloc() moved outisde conditional above
    free(sendpacket);
}

/** 
 * Starts listening for incoming broadcasts, and sends them to be dealt with
 * Thread entry point
 *
 * @param args: The struct contains the name of the interface and the pcap_t pointer
 *
 **/
void *  start_listening(void * args)
{
  const interface_data * iface_data = (interface_data *)args;

  printf("Thread spawned\n");
  while (1)
  {
    if (do_exit) break;
    
    pcap_loop(iface_data->pcap_int, 2, flood_packet, (u_char *)iface_data->interface);
  }
  return NULL;
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

/** 
 * Read a file containing the list of ports to forward. Populate the ports list 
 * var, but not the filter string. There may be >1 ports file, so delay that. 
 *
 * Each line of the file should:
 * - Have any comments preceeded by a # on each line
 * - Have zero or one port number or range per line
 * - Port ranges should be specified like: 9000-9010
 * - 
 *
 * @param in pointer to the file to read
 * @return 0 on success, something else on failure. 
 * */
int parse_ports_file(FILE * in, char * dest[], int * offset)
{
  char line[256];
  char * ptr;
  char * linestart;
//  char * lineend;
  char * comment;

  while (fgets( line, 256, in) != NULL)
  {
    // Stop the string at the comment if there is one
    if ( (comment = strchr(line, COMMENT_CHAR)) != NULL)
      *comment='\0';
    ptr=line;
    // Eat up white space at the start of the line
    while ( *ptr != '\0' && isspace(*ptr) )
      ptr++;
    linestart = ptr;
    // Eat up white space after the content
    while (*ptr != '\0' && isspace(*ptr) == 0)
      ptr++;
    *ptr = '\0';
    if (strlen(linestart) > 0)
    {
      port_list[num_ports] = malloc(strlen(linestart)+1);
      strcpy(port_list[num_ports], linestart);
      num_ports++;
    }


  }
  for (int i = 0; i < num_ports; i++)
    printf("%s\n", port_list[i]);

  return 0;

}

int main(int argc, char * argv[])
{
  pthread_t * threads;
  
  int i;

  if ( getuid() != 0 && geteuid() != 0)
  {
    fprintf(stderr, "Not running program as root. Crashes and segfaults may result.\n");
    fflush(stdout);
  }

  // Read in arguments
  for (i = 1; i < argc; i++)
  {
    if ( strcmp("-p", argv[i]) == 0)
    {
      if (i++ < argc)
      {
        char * filename = argv[i];
        FILE * portfile;
        portfile = fopen(filename, "rt");
        if ( portfile == NULL || parse_ports_file(portfile) != 0)
        {
          fprintf(stderr, "Error opening or parsing the ports list file, %s", filename);
          return -1;
        }
        fclose(portfile);
      }
      else
      {
        fprintf(stderr, "-p specified, but no filename");
        return -1;
      }

    }
    else if (strcmp("-i", argv[i]) == 0)
    {

    }
    else
    {
      fprintf(stderr, "Unknown argument given. Exiting to avoid unexpected actions");
      return -1;
    }

  }

return 0;
  printf("Using filter:%s\n", filter);
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
