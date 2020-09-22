#include <pcap.h>
#include <stdio.h>
#include <libnet.h>

void ipv4_to_string(char* buf, in_addr_t s_addr) {
    u_char bytes[4];

    for (int i=0; i < 4; i++) bytes[i] = (s_addr >> (i*8)) & 0xff;

    sprintf(buf, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
}


void print_ethernet(libnet_ethernet_hdr ethernet_hdr) {
    printf("[ ethernet ]");
    printf("\n\tsrc: %x", ethernet_hdr.ether_shost[0]);
    for (int i=1; i<ETHER_ADDR_LEN; i++) printf(":%x", ethernet_hdr.ether_shost[i]);
    printf("\n\tdst: %x", ethernet_hdr.ether_dhost[0]);
    for (int i=1; i<ETHER_ADDR_LEN; i++) printf(":%x", ethernet_hdr.ether_dhost[i]);
    printf("\n");
}

void print_ipv4(libnet_ipv4_hdr ipv4_hdr) {
    char ipv4_src[16] = { 0, };
    char ipv4_dst[16] = { 0, };

    ipv4_to_string(ipv4_src, ipv4_hdr.ip_src.s_addr);
    ipv4_to_string(ipv4_dst, ipv4_hdr.ip_dst.s_addr);
    printf("[ ipv4 ]\n\tsrc: %s\n\tdst: %s\n", ipv4_src, ipv4_dst);
}

void print_tcp(libnet_tcp_hdr tcp_hdr) {
    printf("[ tcp ]");
    
    printf("\n\tsrc: %d", ntohs(tcp_hdr.th_sport));
    printf("\n\tdst: %d", ntohs(tcp_hdr.th_dport));
    printf("\n");
}

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        printf("\n%u bytes captured\n", header->caplen);

        struct libnet_ethernet_hdr ethernet_hdr;
        struct libnet_ipv4_hdr ipv4_hdr;
        struct libnet_tcp_hdr tcp_hdr;

        memcpy(&ethernet_hdr, packet, 14);
        memcpy(&ipv4_hdr, packet+14, 20);
        memcpy(&tcp_hdr, packet+14+20, 20);

        print_ethernet(ethernet_hdr);
        print_ipv4(ipv4_hdr);
        print_tcp(tcp_hdr);
    }

    pcap_close(handle);
}
