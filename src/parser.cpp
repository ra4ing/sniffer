#include "parser.h"
#include <iostream>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>

PacketParser::PacketParser() {}

ParsedPacket* PacketParser::parsePacket(const struct pcap_pkthdr* header, const u_char* packet) {
    if (header == nullptr || packet == nullptr)
        return nullptr;

    ParsedPacket* parsedPacket = new ParsedPacket();
    parseEthernetHeader(packet, parsedPacket);

    // IP
    if (parsedPacket->etherType == 0x0800) {  // IPv4
        parseIPHeader(packet, parsedPacket);

        // TCP UDP ICMP
        if (parsedPacket->protocol == IPPROTO_TCP)
            parseTCPHeader(packet, parsedPacket);
        else if (parsedPacket->protocol == IPPROTO_UDP)
            parseUDPHeader(packet, parsedPacket);
        else if (parsedPacket->protocol == IPPROTO_ICMP)
            parseICMPHeader(packet, parsedPacket);
        else
            return parsedPacket;
    }
    return parsedPacket;
}

void PacketParser::parseEthernetHeader(const u_char* packet, ParsedPacket* parsedPacket) {
    struct ether_header* ethernetHeader = (struct ether_header*)packet;

    // 解析源和目的 MAC 地址
    parsedPacket->srcMAC = ether_ntoa((struct ether_addr*)ethernetHeader->ether_shost);
    parsedPacket->destMAC = ether_ntoa((struct ether_addr*)ethernetHeader->ether_dhost);

    // 解析以太类型字段
    parsedPacket->etherType = ntohs(ethernetHeader->ether_type);
}

void PacketParser::parseIPHeader(const u_char* packet, ParsedPacket* parsedPacket) {
    const struct ip* ipHeader = (struct ip*)(packet + sizeof(struct ether_header));

    parsedPacket->srcIP = inet_ntoa(ipHeader->ip_src);
    parsedPacket->destIP = inet_ntoa(ipHeader->ip_dst);

    parsedPacket->ipVersion = (ipHeader->ip_v == 4) ? 4 : 6;
    parsedPacket->ttl = ipHeader->ip_ttl;
    parsedPacket->totalLength = ntohs(ipHeader->ip_len);

    parsedPacket->protocol = ipHeader->ip_p;
}

void PacketParser::parseTCPHeader(const u_char* packet, ParsedPacket* parsedPacket) {
    const struct tcphdr* tcpHeader = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));

    parsedPacket->srcPort = std::to_string(ntohs(tcpHeader->source));
    parsedPacket->destPort = std::to_string(ntohs(tcpHeader->dest));

    parsedPacket->seqNumber = ntohl(tcpHeader->seq);
    parsedPacket->ackNumber = ntohl(tcpHeader->ack_seq);

    parsedPacket->tcpFlags = tcpHeader->th_flags;

    parsedPacket->windowSize = ntohs(tcpHeader->window);
}

void PacketParser::parseUDPHeader(const u_char* packet, ParsedPacket* parsedPacket) {
    const struct udphdr* udpHeader = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));

    parsedPacket->srcPort = std::to_string(ntohs(udpHeader->source));
    parsedPacket->destPort = std::to_string(ntohs(udpHeader->dest));
}

void PacketParser::parseICMPHeader(const u_char* packet, ParsedPacket* parsedPacket) {
    const struct icmphdr* icmpHeader = (struct icmphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));

    parsedPacket->icmpType = icmpHeader->type;
    parsedPacket->icmpCode = icmpHeader->code;
}