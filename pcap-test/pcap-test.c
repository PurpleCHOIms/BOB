#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

// libnet-headers.h에서 가져온 구조체들
#define ETHER_ADDR_LEN 6
#define LIBNET_LIL_ENDIAN 1
#define LIBNET_BIG_ENDIAN 0

struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN]; /* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN]; /* source ethernet address */
    u_int16_t ether_type;                  /* protocol */
};

struct libnet_ipv4_hdr
{
    #if (LIBNET_LIL_ENDIAN)
    u_int8_t ip_hl:4,      /* header length */
    ip_v:4;       /* version */
    #endif
    #if (LIBNET_BIG_ENDIAN)
    u_int8_t ip_v:4,       /* version */
    ip_hl:4;      /* header length */
    #endif
    u_int8_t ip_tos;       /* type of service */
    u_int16_t ip_len;      /* total length */
    u_int16_t ip_id;       /* identification */
    u_int16_t ip_off;      /* fragment offset field */
    u_int8_t ip_ttl;       /* time to live */
    u_int8_t ip_p;         /* protocol */
    u_int16_t ip_sum;      /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

struct libnet_tcp_hdr
{
    u_int16_t th_sport;    /* source port */
    u_int16_t th_dport;    /* destination port */
    u_int32_t th_seq;      /* sequence number */
    u_int32_t th_ack;      /* acknowledgement number */
    #if (LIBNET_LIL_ENDIAN)
    u_int8_t th_x2:4,      /* (unused) */
    th_off:4;     /* data offset */
    #endif
    #if (LIBNET_BIG_ENDIAN)
    u_int8_t th_off:4,     /* data offset */
    th_x2:4;      /* (unused) */
    #endif
    u_int8_t th_flags;     /* control flags */
    u_int16_t th_win;      /* window */
    u_int16_t th_sum;      /* checksum */
    u_int16_t th_urp;      /* urgent pointer */
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void print_mac(u_int8_t* mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_hex_data(const u_char* data, int len) {
    int i;
    int max_len = (len > 20) ? 20 : len;  // 최대 20바이트만

    for (i = 0; i < max_len; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (max_len % 16 != 0) printf("\n");
}

void analyze_tcp_packet(const u_char* packet, int packet_len) {
    struct libnet_ethernet_hdr* eth_hdr;
    struct libnet_ipv4_hdr* ip_hdr;
    struct libnet_tcp_hdr* tcp_hdr;
    const u_char* data;
    int eth_len = 14;
    int ip_len, tcp_len, data_len;

    // 이더넷 헤더
    if (packet_len < eth_len) return;
    eth_hdr = (struct libnet_ethernet_hdr*)packet;

    // IPv4 패킷인지 확인
    if (ntohs(eth_hdr->ether_type) != 0x0800) return;

    // IP 헤더
    if (packet_len < eth_len + 20) return;
    ip_hdr = (struct libnet_ipv4_hdr*)(packet + eth_len);

    if (ip_hdr->ip_v != 4) return;

    // TCP 패킷인지 확인
    if (ip_hdr->ip_p != 6) return;

    // IP 헤더 길이 계산
    ip_len = ip_hdr->ip_hl * 4;
    if (packet_len < eth_len + ip_len + 20) return;

    // TCP 헤더 위치
    tcp_hdr = (struct libnet_tcp_hdr*)(packet + eth_len + ip_len);
    tcp_len = tcp_hdr->th_off * 4;

    // 데이터 영역 계산
    data_len = packet_len - eth_len - ip_len - tcp_len;
    data = packet + eth_len + ip_len + tcp_len;

    // 1. src mac -> dst mac
    print_mac(eth_hdr->ether_shost);
    printf(" -> ");
    print_mac(eth_hdr->ether_dhost);
    printf("\n");

    // 2. src ip -> dst ip
    printf("%s -> %s\n", inet_ntoa(ip_hdr->ip_src), inet_ntoa(ip_hdr->ip_dst));

    // 3. src port -> dst port
    printf("%d -> %d\n", ntohs(tcp_hdr->th_sport), ntohs(tcp_hdr->th_dport));

    // 4. payload hexadecimal (최대 20바이트)
    if (data_len > 0) {
        print_hex_data(data, data_len);
    } else {
        printf("(no data)\n");
    }

    // 패킷 구분을 위한 빈 줄
    printf("\n");
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        analyze_tcp_packet(packet, header->caplen);
    }

    pcap_close(pcap);
}
