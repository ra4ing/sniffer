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
    // Ethernet
    std::string srcMAC;
    std::string destMAC;
    uint16_t etherType;

    // IP
    std::string srcIP;
    std::string destIP;
    uint8_t ipVersion;   // IP version (4 or 6)
    uint8_t ttl;         // TTL
    uint16_t totalLength;

    // Transport layer
    uint8_t protocol;
    std::string srcPort;
    std::string destPort;

    // ICMP
    uint8_t icmpType;
    uint8_t icmpCode;

    // TCP
    unsigned int tcpFlags;  // TCP flags
    uint32_t seqNumber;     // Sequence number (TCP)
    uint32_t ackNumber;     // Acknowledgment number (TCP)
    uint16_t windowSize;    // TCP window size

    // Payload
    std::string payload;   // Packet payload data

// Updated toString() method to output more comprehensive information
    std::string toString() const {
        std::ostringstream oss;

        // Display Ethernet layer information
        oss << "Ethernet Frame:\n"
            << "  Source MAC: " << srcMAC << "\n"
            << "  Destination MAC: " << destMAC << "\n"
            << "  EtherType: 0x" << std::hex << etherType << "\n\n";

        // Display IP layer information (check for IPv4 or IPv6)
        if (etherType == 0x0800) {  // IPv4
            oss << "IPv4 Packet:\n"
                << "  Source IP: " << srcIP << "\n"
                << "  Destination IP: " << destIP << "\n"
                << "  TTL: " << std::dec << (int)ttl << "\n"
                << "  Total Length: " << totalLength << " bytes\n";
        } else if (etherType == 0x86DD) {  // IPv6 (add IPv6 support if needed)
            oss << "IPv6 Packet:\n"
                << "  Source IP: " << srcIP << "\n"
                << "  Destination IP: " << destIP << "\n";
        }

        // Display Transport layer information
        std::string protoStr;
        if (protocol == IPPROTO_TCP)
            protoStr = "TCP";
        else if (protocol == IPPROTO_UDP)
            protoStr = "UDP";
        else if (protocol == IPPROTO_ICMP)
            protoStr = "ICMP";
        else
            protoStr = "other";

        oss << "Transport Layer (" << protoStr << "):\n";

        if (protocol == IPPROTO_TCP) {
            // TCP-specific information
            oss << "  Source Port: " << srcPort << "\n"
                << "  Destination Port: " << destPort << "\n"
                << "  Sequence Number: " << seqNumber << "\n"
                << "  Acknowledgment Number: " << ackNumber << "\n"
                << "  TCP Flags: 0x" << std::hex << tcpFlags << "\n"
                << "  Window Size: " << std::dec << windowSize << "\n";
        } else if (protocol == IPPROTO_UDP) {
            // UDP-specific information
            oss << "  Source Port: " << srcPort << "\n"
                << "  Destination Port: " << destPort << "\n";
        } else if (protocol == IPPROTO_ICMP) {
            // ICMP-specific information
            oss << "  ICMP Type: " << (int)icmpType << "\n"
                << "  ICMP Code: " << (int)icmpCode << "\n";
        }

        // Display Payload information
        oss << "\nPayload: " << payload << "\n";
        
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