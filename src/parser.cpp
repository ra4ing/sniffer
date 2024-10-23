#include "parser.h"
#include <iostream>
#include <arpa/inet.h>

PacketParser::PacketParser() {}

ParsedPacket* PacketParser::parsePacket(const struct pcap_pkthdr* header, const u_char* packet) {
    if (header == nullptr || packet == nullptr)
        return nullptr;

    ParsedPacket* parsedPacket = new ParsedPacket();
    parseEthernetHeader(packet, parsedPacket);
    parseIPHeader(packet, parsedPacket);

    if (parsedPacket->protocol == IPPROTO_TCP)
        parseTCPHeader(packet, parsedPacket);
    else if (parsedPacket->protocol == IPPROTO_UDP)
        parseUDPHeader(packet, parsedPacket);

    return parsedPacket;
}

void PacketParser::parseEthernetHeader(const u_char* packet, ParsedPacket* parsedPacket) {
    struct ether_header* eth_header = (struct ether_header*)packet;
    char mac[18];

    snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
        eth_header->ether_shost[0],
        eth_header->ether_shost[1],
        eth_header->ether_shost[2],
        eth_header->ether_shost[3],
        eth_header->ether_shost[4],
        eth_header->ether_shost[5]
    );
    parsedPacket->srcMAC = std::string(mac);

    snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
        eth_header->ether_dhost[0],
        eth_header->ether_dhost[1],
        eth_header->ether_dhost[2],
        eth_header->ether_dhost[3],
        eth_header->ether_dhost[4],
        eth_header->ether_dhost[5]
    );
    parsedPacket->srcMAC = std::string(mac);
}

void PacketParser::parseIPHeader(const u_char* packet, ParsedPacket* parsedPacket) {
    struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));
    parsedPacket->srcIP = std::string(inet_ntoa(ip_header->ip_src));
    parsedPacket->destIP = std::string(inet_ntoa(ip_header->ip_dst));

    parsedPacket->protocol = ip_header->ip_p;
}

void PacketParser::parseTCPHeader(const u_char* packet, ParsedPacket* parsedPacket) {
    struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));
    struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + ip_header->ip_hl * 4);

    parsedPacket->srcPort = std::to_string(ntohs(tcp_header->source));
    parsedPacket->destPort = std::to_string(ntohs(tcp_header->dest));
    parsedPacket->tcpFlags = tcp_header->th_flags;
}

void PacketParser::parseUDPHeader(const u_char* packet, ParsedPacket* parsedPacket) {
    struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));
    struct udphdr* udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + ip_header->ip_hl * 4);

    parsedPacket->srcPort = std::to_string(ntohs(udp_header->source));
    parsedPacket->destPort = std::to_string(ntohs(udp_header->dest));
}



// void PacketParser::parseICMPHeader(const u_char* packet, ParsedPacket& parsedPacket) {
//     struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));
//     struct tcphdr* icmp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + ip_header->ip_hl * 4);

//     parsedPacket.srcPort = std::to_string(ntohs(udp_header->source));
//     parsedPacket.destPort = std::to_string(ntohs(udp_header->dest));
// }