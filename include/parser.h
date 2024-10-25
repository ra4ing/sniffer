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
#include <netinet/igmp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <sstream>
#include <map>

struct DNSHeader {
    uint16_t id;       // ID
    uint16_t flags;    // 标志位
    uint16_t qdcount;  // 问题数量
    uint16_t ancount;  // 应答数量
    uint16_t nscount;  // 授权数量
    uint16_t arcount;  // 附加数量
};

struct ARPHeader {
    unsigned short int ar_hrd;      // Format of hardware address
    unsigned short int ar_pro;      // Format of protocol address
    unsigned char ar_hln;           // Length of hardware address
    unsigned char ar_pln;           // Length of protocol address
    unsigned short int ar_op;       // ARP opcode (1 for request, 2 for reply)
    unsigned char ar_sha[6];        // Sender hardware address (MAC)
    unsigned char ar_sip[4];        // Sender IP address
    unsigned char ar_tha[6];        // Target hardware address (MAC)
    unsigned char ar_tip[4];        // Target IP address
};

// ICMP 类型描述映射
const std::map<uint8_t, std::string> icmpTypeDescriptions = {
    {0, "Echo Reply (0)"},
    {3, "Destination Unreachable (3)"},
    {4, "Source Quench (4)"},
    {5, "Redirect (5)"},
    {8, "Echo Request (8)"},
    {11, "Time Exceeded (11)"},
    {12, "Parameter Problem (12)"}
};

// ICMP 代码描述映射（针对类型 3: Destination Unreachable）
const std::map<uint8_t, std::string> icmpCodeDestUnreachable = {
    {0, "Net Unreachable (0)"},
    {1, "Host Unreachable (1)"},
    {2, "Protocol Unreachable (2)"},
    {3, "Port Unreachable (3)"}
};

// ICMP 代码描述映射（针对类型 11: Time Exceeded）
const std::map<uint8_t, std::string> icmpCodeTimeExceeded = {
    {0, "TTL Expired (0)"},
    {1, "Fragment Reassembly Time Exceeded (1)"}
};

typedef struct ParsedPacket {
    // Ethernet
    std::string srcMAC;
    std::string destMAC;
    uint16_t etherType;

    // ARP
    unsigned short hardwareType;
    unsigned short protocolType;

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

    // IGMP
    uint8_t igmpType;
    uint8_t maxResponseTime;
    std::string groupAddr;

    // TCP
    unsigned int tcpFlags;  // TCP flags
    uint32_t seqNumber;     // Sequence number (TCP)
    uint32_t ackNumber;     // Acknowledgment number (TCP)
    uint16_t windowSize;    // TCP window size

    // Payload
    std::string payload;   // Packet payload data
}ParsedPacket;


class PacketParser {
public:
    PacketParser();

    ParsedPacket* parsePacket(const struct pcap_pkthdr* header, const u_char* packet);

private:
    void parseEthernetHeader(const u_char* packet, ParsedPacket* parsedPacket);
    void parseARPHeader(const u_char* packet, ParsedPacket* parsedPacket);
    void parseIPHeader(const u_char* packet, ParsedPacket* parsedPacket);
    void parseTCPHeader(const u_char* packet, ParsedPacket* parsedPacket);
    void parseUDPHeader(const u_char* packet, ParsedPacket* parsedPacket);
    void parseICMPHeader(const u_char* packet, ParsedPacket* parsedPacket);
    void parseIGMPHeader(const u_char* packet, ParsedPacket* parsedPacket);

    void parseHTTP(const u_char* packet, ParsedPacket* parsedPacket);
    void parseHTTPS(const u_char* packet, ParsedPacket* parsedPacket);
    void parseDNS(const u_char* packet, ParsedPacket* parsedPacket);
    void parseFTP(const u_char* packet, ParsedPacket* parsedPacket);

    std::string parseDNSName(const u_char* packet, size_t& offset);
    std::vector<ParsedPacket> parsedPackets;
};

#endif