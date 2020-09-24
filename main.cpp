#include <pcap.h>
#include <stdio.h>
#include <libnet.h>

char* ipv4_to_string(in_addr_t s_addr) {
    u_char bytes[4];
    static char buf[16];

    for (int i=0; i < 4; i++) bytes[i] = (s_addr >> (i*8)) & 0xff;

    sprintf(buf, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
    return buf;
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
    printf("[ ipv4 ]");
    printf("\n\tsrc: %s", ipv4_to_string(ipv4_hdr.ip_src.s_addr));
    printf("\n\tdst: %s\n", ipv4_to_string(ipv4_hdr.ip_dst.s_addr));
}

void print_tcp(libnet_tcp_hdr tcp_hdr) {
    printf("[ tcp ]");
    printf("\n\tsrc: %d", ntohs(tcp_hdr.th_sport));
    printf("\n\tdst: %d\n", ntohs(tcp_hdr.th_dport));
}

void print_data(const u_char* data) {
    printf("[ data ]");
    for (int i = 0; i<16; i++) {
        if (data[i] == EOF) return;
        printf("%02x ", data[i]);
    }
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

        memcpy(&ethernet_hdr, packet, sizeof(libnet_ethernet_hdr));
        memcpy(&ipv4_hdr, packet+sizeof(libnet_ethernet_hdr), sizeof(libnet_ipv4_hdr));
        memcpy(&tcp_hdr, packet+sizeof(libnet_ethernet_hdr)+sizeof(libnet_ipv4_hdr), sizeof(libnet_tcp_hdr));

        print_ethernet(ethernet_hdr);
        if (ethernet_hdr.ether_type != ETHERTYPE_IP) {
            printf("Not ipv4.\n");
            return 0;
        }
        print_ipv4(ipv4_hdr);
        if (ipv4_hdr.ip_p != IPPROTO_TCP) {
            printf("Not tcp\n");
            return 0;
        }
        print_tcp(tcp_hdr);
        print_data(packet+sizeof(libnet_ethernet_hdr)+sizeof(libnet_ipv4_hdr)+sizeof(libnet_tcp_hdr));
    }

    pcap_close(handle);
}
