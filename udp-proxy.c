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
 * gcc -o udp-proxy udp-proxy.c -lpcap
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

#define OUTPUT_INT "eth1"
#define INPUT_INT "eth0"
#define SNAP_LEN 1540
#define PROMISC 1
#define TIMEOUT 10

struct bpf_program  fp;

char filter[] = "udp and port 27015";

char pcap_errbuf[PCAP_ERRBUF_SIZE] = "\0";
pcap_t* int_in;
pcap_t* int_out;

void flood_packet( u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  printf("Packet length %d", header->len);
  pcap_inject(int_out, packet, header->len);
}

int main()
{

  const u_char *packet;
  struct pcap_pkthdr header;
  char * args;

  int_in = pcap_open_live(INPUT_INT, SNAP_LEN, PROMISC, TIMEOUT, pcap_errbuf); 
  int_out = pcap_open_live(OUTPUT_INT, SNAP_LEN, 0, TIMEOUT, pcap_errbuf);

  if (int_in == NULL) { fprintf(stderr, "Error opening dev"); return (2); }


    /// 
  if ( pcap_compile(int_in, &fp, filter, 0, 0 ) == -1 ) {
      fprintf(stderr, "Error compiling filter");
      return (2);
  }

  if (pcap_setfilter(int_in, &fp) == -1 ) {
    fprintf(stderr, "Error setting filter");
    return (2);
  }

  if (pcap_setdirection(int_in, PCAP_D_IN) == -1) {
    fprintf(stderr, "Error setting direction");
    return (2);
  }

  args = "eth0";
  pcap_loop( int_in, 2, flood_packet, args);

  pcap_close(int_in);
  return 0;
}
