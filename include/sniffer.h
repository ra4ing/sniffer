#ifndef SNIFFER_H
#define SNIFFER_H

#include <pcap.h>
#include <string>
#include <functional>

class Sniffer {
public:
    Sniffer(
        int snaplen_ = BUFSIZ,
        int promisc_ = 1,
        int to_ms_ = 1000);
    ~Sniffer();

    int isCapturing;

    pcap_if_t* getDevs();                           // 获取设备列表
    bool openDev();                                 // 打开设备
    void closeDev();                                // 关闭设备
    bool setSniffer(                                // 设置嗅探器参数
        std::string devName_,
        int snaplen_ = -1,
        int promisc_ = -1,
        int to_ms_ = -1);
    void startCapture(std::function<void(u_char* user, const struct pcap_pkthdr* header, const u_char* packet)> packetHandler);                                 // 开始捕获数据包
    void stopCapture();                             // 停止捕获
    int applyFilter(const std::string& filter);     // 应用数据包过滤规则
    int savePacket(const std::string& filename, const struct pcap_pkthdr* header, const u_char* packet);  // 保存捕获的数据包
    int saveAllPackets(const std::string& filename, const std::vector<const pcap_pkthdr*>& headers, const std::vector<const u_char*>& packets);
    bool openPacket(const std::string& filename, std::function<void(u_char* user, const struct pcap_pkthdr* header, const u_char* packet)> packetHandler);
    int filterCapturedPackets(const std::string& filter,
        std::vector<const pcap_pkthdr*>& headers,
        std::vector<const u_char*>& packets,
        std::vector<int>& filteredIndex);

private:
    std::string devName;
    int snaplen;
    int promisc;
    int to_ms;

    pcap_if_t* allDevs;             // 设备列表
    pcap_t* handle;                 // 捕获句柄
    char errBuf[PCAP_ERRBUF_SIZE];  // 错误缓冲区
};

#endif // SNIFFER_H
