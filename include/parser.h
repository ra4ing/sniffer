#ifndef PACKETPARSER_H
#define PACKETPARSER_H

#include <pcap.h>
#include <string>
#include <vector>
#include <map>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

class PacketParser {
public:
    PacketParse();

    void parsePacket(const struct pcap_pkthdr* header, const u_char* packet);


private:
    void parseEthernetHeader(const u_char* packet);
    void parseIPHeader(const u_char* packet);
    void parseTCPHeader(const u_char* packet);
    void parseUDPHeader(const u_char* packet);

};

#endif