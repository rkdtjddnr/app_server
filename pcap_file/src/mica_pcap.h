#include <stdio.h>
#include <pcap/pcap.h>
#include <time.h>
#include <rte_mbuf_core.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>

#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4

#define IPV4_HDR_SIZE sizeof(struct rte_ipv4_hdr)
#define UDP_HDR_SIZE sizeof(struct rte_udp_hdr)
#define SNAPLEN 65536

#define CLIENT_IP 0x0A000204  // 10.0.2.4
#define SERVER_IP 0x0A000201  // 10.0.2.1
#define CLIENT_PORT 11211     // UDP Source Port
#define SERVER_PORT 11211     // UDP Destination Port

// TIME INTERVAL
#pragma pack(1)
struct pcap_timeval {
	bpf_u_int32 tv_sec;	/* seconds */
	bpf_u_int32 tv_usec;	/* microseconds */
};

// PACKET HEADER
struct pcap_sf_pkthdr {
	struct pcap_timeval ts;	/* time stamp */
	bpf_u_int32 caplen;	/* length of portion present */
	bpf_u_int32 len;	/* length of this packet (off wire) */
};
#pragma pack()

typedef enum PktType {RX, TX} PKTTYPE;
typedef enum AppType {MICA, MEMCACHED} APPTYPE;

void write_pcap_header(FILE *fp);

void save_packet_to_pcap(struct rte_mbuf *mbuf, const char* filename, FILE* my_pcap_file) ;

void save_packet_memcached(struct rte_mbuf *mbuf, const char* filename, FILE* my_pcap_file, PKTTYPE pkttype);

const char* get_filename(int core, int key_len, int val_len, int num_op, int batch_size, double get_ratio, APPTYPE apptype);
