#include "parser.h"
#include <iostream>
#include <regex>

PacketParser::PacketParser() {}

ParsedPacket* PacketParser::parsePacket(const struct pcap_pkthdr* header, const u_char* packet) {
    if (header == nullptr || packet == nullptr)
        return nullptr;

    ParsedPacket* parsedPacket = new ParsedPacket();
    parseEthernetHeader(packet, parsedPacket);

    // IP
    if (parsedPacket->etherType == ETHERTYPE_IP) {  // IPv4
        parseIPHeader(packet, parsedPacket);
        // TCP UDP ICMP IGMP
        if (parsedPacket->protocol == IPPROTO_TCP) {
            parseTCPHeader(packet, parsedPacket);
            if (parsedPacket->srcPort == "80" || parsedPacket->destPort == "80")
                parseHTTP(packet, parsedPacket);
            else if (parsedPacket->srcPort == "443" || parsedPacket->destPort == "443")
                parseHTTPS(packet, parsedPacket);
        }
        else if (parsedPacket->protocol == IPPROTO_UDP) {
            parseUDPHeader(packet, parsedPacket);
            if (parsedPacket->srcPort == "53" || parsedPacket->destPort == "53")
                parseDNS(packet, parsedPacket);
        }
        else if (parsedPacket->protocol == IPPROTO_ICMP)
            parseICMPHeader(packet, parsedPacket);
        else if (parsedPacket->protocol == IPPROTO_IGMP)
            parseIGMPHeader(packet, parsedPacket);
        else
            return parsedPacket;
    }
    else if (parsedPacket->etherType == ETHERTYPE_ARP)  // ARP
        parseARPHeader(packet, parsedPacket);

        return parsedPacket;
}

void PacketParser::parseEthernetHeader(const u_char* packet, ParsedPacket* parsedPacket) {
    struct ether_header* ethernetHeader = (struct ether_header*)packet;

    parsedPacket->srcMAC = ether_ntoa((struct ether_addr*)ethernetHeader->ether_shost);
    parsedPacket->destMAC = ether_ntoa((struct ether_addr*)ethernetHeader->ether_dhost);

    parsedPacket->etherType = ntohs(ethernetHeader->ether_type);
}

void PacketParser::parseARPHeader(const u_char* packet, ParsedPacket* parsedPacket) {
    const struct ARPHeader* arpHeader = (struct ARPHeader*)(packet + sizeof(struct ether_header));

    // ARP 操作码（命令）: 1 表示请求，2 表示响应
    parsedPacket->protocol = ntohs(arpHeader->ar_op);

    // 硬件类型和协议类型
    unsigned short hardwareType = ntohs(arpHeader->ar_hrd);
    unsigned short protocolType = ntohs(arpHeader->ar_pro);

    // 硬件地址和协议地址格式
    parsedPacket->etherType = protocolType;

    // 源 MAC 地址
    char srcMAC[18];
    snprintf(srcMAC, sizeof(srcMAC), "%02x:%02x:%02x:%02x:%02x:%02x",
             arpHeader->ar_sha[0], arpHeader->ar_sha[1], arpHeader->ar_sha[2],
             arpHeader->ar_sha[3], arpHeader->ar_sha[4], arpHeader->ar_sha[5]);
    parsedPacket->srcMAC = srcMAC;

    // 目标 MAC 地址
    char destMAC[18];
    snprintf(destMAC, sizeof(destMAC), "%02x:%02x:%02x:%02x:%02x:%02x",
             arpHeader->ar_tha[0], arpHeader->ar_tha[1], arpHeader->ar_tha[2],
             arpHeader->ar_tha[3], arpHeader->ar_tha[4], arpHeader->ar_tha[5]);
    parsedPacket->destMAC = destMAC;

    // 源 IP 地址
    parsedPacket->srcIP = std::to_string(arpHeader->ar_sip[0]) + "." +
                          std::to_string(arpHeader->ar_sip[1]) + "." +
                          std::to_string(arpHeader->ar_sip[2]) + "." +
                          std::to_string(arpHeader->ar_sip[3]);

    // 目标 IP 地址
    parsedPacket->destIP = std::to_string(arpHeader->ar_tip[0]) + "." +
                           std::to_string(arpHeader->ar_tip[1]) + "." +
                           std::to_string(arpHeader->ar_tip[2]) + "." +
                           std::to_string(arpHeader->ar_tip[3]);
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

void PacketParser::parseHTTP(const u_char* packet, ParsedPacket* parsedPacket) {

    const u_char* payload = packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr);
    size_t payloadSize = ntohs(((struct ip*)(packet + sizeof(struct ether_header)))->ip_len) -
            (sizeof(struct ip) + sizeof(struct tcphdr));
        
    // 将负载转换为字符串
    std::string httpData(reinterpret_cast<const char*>(payload), payloadSize);

    // 检查是否为 HTTP 请求或响应
    if (std::regex_search(httpData, std::regex(R"(^GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)"))) {
        // 解析 HTTP 请求
        parsedPacket->payload = "HTTP Request: " + httpData;
        // std::istringstream stream(httpData);
        // std::string method, url, version;
        // stream >> method >> url >> version;
        
        // std::cout << "HTTP Request - Method: " << method << ", URL: " << url << ", Version: " << version << std::endl;
    } 
    else if (std::regex_search(httpData, std::regex(R"(^HTTP/\d\.\d \d{3})"))) {
        // 解析 HTTP 响应
        parsedPacket->payload = "HTTP Response: " + httpData;
        // std::istringstream stream(httpData);
        // std::string version, statusCode, statusMessage;
        // stream >> version >> statusCode;
        // std::getline(stream, statusMessage);
        
        // std::cout << "HTTP Response - Version: " << version << ", Status Code: " << statusCode 
        //           << ", Status Message: " << statusMessage << std::endl;
    } else {
        parsedPacket->payload = "Unknown HTTP Content";
    }
}

void PacketParser::parseHTTPS(const u_char* packet, ParsedPacket* parsedPacket) {
    const u_char* payload = packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr);
    size_t payloadSize = ntohs(((struct ip*)(packet + sizeof(struct ether_header)))->ip_len) -
                             (sizeof(struct ip) + sizeof(struct tcphdr));
        
    // 检查 TLS 握手的第一个字节（内容类型），0x16 表示 Handshake
    if (payloadSize > 0 && payload[0] == 0x16) {
        // 进一步检查握手协议版本（如 TLS 1.0/1.2/1.3）
        uint16_t version = (payload[1] << 8) | payload[2];
        parsedPacket->payload = "Detected TLS Handshake, Version: " + std::to_string(version);

        // std::cout << "TLS Handshake Detected - Version: " << std::hex << version << std::endl;
    } else {
        parsedPacket->payload = "Encrypted HTTPS Content";
    }
}

void PacketParser::parseUDPHeader(const u_char* packet, ParsedPacket* parsedPacket) {
    const struct udphdr* udpHeader = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));

    parsedPacket->srcPort = std::to_string(ntohs(udpHeader->source));
    parsedPacket->destPort = std::to_string(ntohs(udpHeader->dest));
}

std::string PacketParser::parseDNSName(const u_char* packet, size_t& offset) {
    std::string name;
    while (packet[offset] != 0) {
        int labelLength = packet[offset];
        offset++;
        name.append(reinterpret_cast<const char*>(packet + offset), labelLength);
        offset += labelLength;
        if (packet[offset] != 0) {
            name += ".";
        }
    }
    offset++;
    return name;
}

void PacketParser::parseDNS(const u_char* packet, ParsedPacket* parsedPacket) {
    const u_char* payload = packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr);
    size_t payloadSize = ntohs(((struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip)))->len) - sizeof(struct udphdr);

    if (payloadSize < sizeof(DNSHeader)) {
        std::cerr << "Invalid DNS packet size." << std::endl;
        parsedPacket->payload = "Invalid DNS packet size";
        return;
    }

    const DNSHeader* dnsHeader = reinterpret_cast<const DNSHeader*>(payload);
    uint16_t qdcount = ntohs(dnsHeader->qdcount);
    uint16_t ancount = ntohs(dnsHeader->ancount);

    // 解析 DNS 问题部分
    size_t offset = sizeof(DNSHeader);
    std::ostringstream dnsData;
    dnsData << "DNS Questions:\n";
    for (int i = 0; i < qdcount; ++i) {
        std::string qname = parseDNSName(payload, offset);
        uint16_t qtype = ntohs(*reinterpret_cast<const uint16_t*>(payload + offset));
        offset += 2;
        uint16_t qclass = ntohs(*reinterpret_cast<const uint16_t*>(payload + offset));
        offset += 2;

        dnsData << "  Name: " << qname << ", Type: " << qtype << ", Class: " << qclass << "\n";
    }

    // 解析 DNS 应答部分
    dnsData << "DNS Answers:\n";
    for (int i = 0; i < ancount; ++i) {
        std::string name = parseDNSName(payload, offset);
        uint16_t type = ntohs(*reinterpret_cast<const uint16_t*>(payload + offset));
        offset += 2;
        uint16_t classCode = ntohs(*reinterpret_cast<const uint16_t*>(payload + offset));
        offset += 2;
        uint32_t ttl = ntohl(*reinterpret_cast<const uint32_t*>(payload + offset));
        offset += 4;
        uint16_t dataLen = ntohs(*reinterpret_cast<const uint16_t*>(payload + offset));
        offset += 2;

        // 解析不同类型的 DNS 数据
        std::string data;
        if (type == 1 && dataLen == 4) { // A 记录 (IPv4)
            struct in_addr addr;
            std::memcpy(&addr, payload + offset, 4);
            data = inet_ntoa(addr);
        } else if (type == 28 && dataLen == 16) { // AAAA 记录 (IPv6)
            char ip6[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, payload + offset, ip6, sizeof(ip6));
            data = ip6;
        } else {
            data = "Unsupported record type";
        }

        offset += dataLen;

        dnsData << "  Name: " << name << ", Type: " << type 
                << ", Class: " << classCode << ", TTL: " << ttl 
                << ", Data: " << data << "\n";
    }

    // 将解析的内容存入 parsedPacket
    parsedPacket->payload = dnsData.str();
}

void PacketParser::parseICMPHeader(const u_char* packet, ParsedPacket* parsedPacket) {
    const struct icmphdr* icmpHeader = (struct icmphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));

    parsedPacket->icmpType = icmpHeader->type;
    parsedPacket->icmpCode = icmpHeader->code;
}

void PacketParser::parseIGMPHeader(const u_char* packet, ParsedPacket* parsedPacket) {
    const struct igmp* igmpHeader = (struct igmp*)(packet + sizeof(struct ether_header) + sizeof(struct ip));

    parsedPacket->igmpType = igmpHeader->igmp_type;
    parsedPacket->maxResponseTime = igmpHeader->igmp_code;

    struct in_addr groupAddr = igmpHeader->igmp_group;
    parsedPacket->groupAddr = inet_ntoa(groupAddr);
}