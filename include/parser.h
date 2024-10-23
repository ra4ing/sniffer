#ifndef PARSER_H
#define PARSER_H

#include <pcap.h>
#include <string>
#include <vector>
#include <map>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <sstream>

typedef struct ParsedPacket {
    std::string srcMAC;
    std::string destMAC;
    std::string srcIP;
    std::string destIP;
    uint8_t protocol;
    std::string srcPort;
    std::string destPort;
    std::string payload;

    std::string toString() const {
        std::string protoStr;

        if (protocol == IPPROTO_TCP)
            protoStr = "TCP";
        else if (protocol == IPPROTO_UDP)
            protoStr = "UDP";
        else if (protocol == IPPROTO_ICMP)
            protoStr = "ICMP";
        else
            protoStr = "other";
        
        std::ostringstream oss;
        oss << "Source MAC: " << srcMAC << "\n"
            << "Destination MAC: " << destMAC << "\n"
            << "Source IP: " << srcIP << "\n"
            << "Destination IP: " << destIP << "\n"
            << "Protocol: " << protocol << "\n"
            << "Source Port: " << srcPort << "\n"
            << "Destination Port: " << destPort << "\n"
            << "Payload: " << payload << "\n";
        return oss.str();
    }
}ParsedPacket;


class PacketParser {
public:
    PacketParser();

    ParsedPacket* parsePacket(const struct pcap_pkthdr* header, const u_char* packet);

private:
    void parseEthernetHeader(const u_char* packet, ParsedPacket* parsedPacket);
    void parseIPHeader(const u_char* packet, ParsedPacket* parsedPacket);
    void parseTCPHeader(const u_char* packet, ParsedPacket* parsedPacket);
    void parseUDPHeader(const u_char* packet, ParsedPacket* parsedPacket);
    void parseICMPHeader(const u_char* packet, ParsedPacket* parsedPacket);

    std::vector<ParsedPacket> parsedPackets;
};

#endif