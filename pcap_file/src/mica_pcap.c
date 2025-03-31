#include "mica_pcap.h"
#include <stdio.h>
// global header 구성하는 함수
void write_pcap_header(FILE *fp)
{
	struct pcap_file_header hdr;

	hdr.magic = 0xa1b2c3d4;
	hdr.version_major = PCAP_VERSION_MAJOR;
	hdr.version_minor = PCAP_VERSION_MINOR;
	hdr.thiszone = 0;
	hdr.sigfigs = 0;
	hdr.snaplen = SNAPLEN;
	hdr.linktype = DLT_EN10MB;

	if (fwrite((char *)&hdr, sizeof(hdr), 1, fp) != 1)
		fprintf(stderr, "[ERROR] Can't open file\n");
    fflush(fp);
	
}

void save_packet_to_pcap(struct rte_mbuf *mbuf, const char* filename, FILE* my_pcap_file) 
{
    struct pcap_sf_pkthdr pcap_pkt_hdr;

    struct timespec tspec;
    clock_gettime(CLOCK_REALTIME, &tspec);

    uint32_t pkt_len = mbuf->pkt_len;
    if (pkt_len > SNAPLEN) {
        fprintf(stderr, "Warning: Paacket size (%u) exceeds SNAPLEN (%d), truncating.\n", pkt_len, SNAPLEN);
        pkt_len = SNAPLEN;
    }

    uint16_t data_len = mbuf->data_len;

    pcap_pkt_hdr.ts.tv_sec = tspec.tv_sec;
    pcap_pkt_hdr.ts.tv_usec = tspec.tv_nsec / 1000;

    pcap_pkt_hdr.caplen = pkt_len + IPV4_HDR_SIZE + UDP_HDR_SIZE;
    pcap_pkt_hdr.len = pkt_len + IPV4_HDR_SIZE + UDP_HDR_SIZE;

    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)((uint8_t *)eth_hdr + sizeof(struct rte_ether_hdr));        
    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)((uint8_t *)ipv4_hdr + sizeof(struct rte_ipv4_hdr));

    uint8_t *payload = (uint8_t *)udp_hdr + sizeof(struct rte_udp_hdr);
    uint16_t payload_size = mbuf->data_len - sizeof(struct rte_ether_hdr);
            
    my_pcap_file = fopen(filename, "ab");
    if (!my_pcap_file) {
        fprintf(stderr, "Error: Failed to open PCAP filee for writing!\n");
        return;
    }
    

    fwrite(&pcap_pkt_hdr, sizeof(pcap_pkt_hdr), 1, my_pcap_file);
    fwrite(eth_hdr, sizeof(struct rte_ether_hdr), 1, my_pcap_file);
    fwrite(ipv4_hdr, IPV4_HDR_SIZE, 1, my_pcap_file);
    fwrite(udp_hdr, UDP_HDR_SIZE, 1, my_pcap_file);                                                  
    fwrite(payload, payload_size, 1, my_pcap_file);
    fflush(my_pcap_file); 
    fclose(my_pcap_file);
}


void save_packet_memcached(struct rte_mbuf *mbuf, const char* filename,FILE* my_pcap_file, PKTTYPE pkttype) {
            
            struct pcap_sf_pkthdr pcap_pkt_hdr;

            struct timespec tspec;
            clock_gettime(CLOCK_REALTIME, &tspec);

            uint32_t pkt_len = mbuf->pkt_len;
            if (pkt_len > SNAPLEN) {
                fprintf(stderr, "Warning: Paacket size (%u) exceeds SNAPLEN (%d), truncating.\n", pkt_len, SNAPLEN);
                pkt_len = SNAPLEN;
            }

            uint16_t data_len = mbuf->data_len;

            pcap_pkt_hdr.ts.tv_sec = tspec.tv_sec;
            pcap_pkt_hdr.ts.tv_usec = tspec.tv_nsec / 1000;

            pcap_pkt_hdr.caplen = pkt_len + IPV4_HDR_SIZE + UDP_HDR_SIZE;
            pcap_pkt_hdr.len = pkt_len + IPV4_HDR_SIZE + UDP_HDR_SIZE;
            


            struct rte_ether_hdr
            *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
            
            
            uint8_t *payload = (uint8_t *)(eth_hdr + 1);
            uint16_t payload_size = mbuf->data_len - sizeof(struct rte_ether_hdr);

            struct rte_ipv4_hdr ipv4_hdr;
            memset(&ipv4_hdr, 0, IPV4_HDR_SIZE);
            ipv4_hdr.version_ihl = (4 << 4) | (IPV4_HDR_SIZE / 4); 
            ipv4_hdr.total_length = rte_cpu_to_be_16(IPV4_HDR_SIZE + UDP_HDR_SIZE + payload_size);
            ipv4_hdr.packet_id = rte_cpu_to_be_16(0); 
            ipv4_hdr.fragment_offset = rte_cpu_to_be_16(0); 
            ipv4_hdr.time_to_live = 64;
            ipv4_hdr.next_proto_id = IPPROTO_UDP;
            
            

            struct rte_udp_hdr udp_hdr;
            memset(&udp_hdr, 0, UDP_HDR_SIZE);
            udp_hdr.dgram_len = rte_cpu_to_be_16(UDP_HDR_SIZE + payload_size);


            if(pkttype == RX)
            {
                ipv4_hdr.src_addr = rte_cpu_to_be_32(CLIENT_IP);
                ipv4_hdr.dst_addr = rte_cpu_to_be_32(SERVER_IP);
                udp_hdr.src_port = rte_cpu_to_be_16(CLIENT_PORT); 
                udp_hdr.dst_port = rte_cpu_to_be_16(SERVER_PORT); 
            } 
            else{
                ipv4_hdr.src_addr = rte_cpu_to_be_32(SERVER_IP);
                ipv4_hdr.dst_addr = rte_cpu_to_be_32(CLIENT_IP);
                udp_hdr.src_port = rte_cpu_to_be_16(SERVER_PORT); 
                udp_hdr.dst_port = rte_cpu_to_be_16(CLIENT_PORT); 
            }

            my_pcap_file = fopen(filename, "ab");
            if (!my_pcap_file) {
                fprintf(stderr, "Error: Failed to open PCAP filee for writing!\n");
                return;
            }
            

            fwrite(&pcap_pkt_hdr, sizeof(pcap_pkt_hdr), 1, my_pcap_file);
            fwrite(eth_hdr, sizeof(struct rte_ether_hdr), 1, my_pcap_file);
            fwrite(&ipv4_hdr, IPV4_HDR_SIZE, 1, my_pcap_file);
            fwrite(&udp_hdr, UDP_HDR_SIZE, 1, my_pcap_file);                                                  
            fwrite(payload, payload_size, 1, my_pcap_file);
            fflush(my_pcap_file); 
            fclose(my_pcap_file);

}

const char* get_filename(int core, int key_len, int val_len, int num_op, int batch_size, double get_ratio, APPTYPE apptype) {
    static char full_path[128]; 
    const char *MICA_DIR = "/home/ubuntu/app_server/pcap_file/mica/";
    const char *MEMCACHED_DIR = "/home/ubuntu/app_server/pcap_file/memcached/";
    char file_name[64];
    
    switch(apptype)
    {
        case MICA:
            snprintf(file_name, sizeof(file_name), "mica_%d_%d_%d_%d_%d_get_%d.pcap", core, key_len, val_len, num_op, batch_size, (int)(get_ratio * 100));
            snprintf(full_path, sizeof(full_path), "%s%s", MICA_DIR, file_name);
            break;

        case MEMCACHED:
            snprintf(file_name, sizeof(file_name), "memcached_%d_%d_%d_%d_get_%d.pcap",key_len, val_len, num_op, batch_size, (int)(get_ratio * 100));
            snprintf(full_path, sizeof(full_path), "%s%s", MEMCACHED_DIR, file_name);
            break;

        default:
            fprintf(stderr, "[ERROR] Wrong application type\n");
            return NULL;
    }

    return full_path;  // OK: static 변수이므로 메모리 유효
}

