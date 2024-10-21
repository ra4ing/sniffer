#ifndef SNIFFER_H
#define SNIFFER_H

#include <pcap.h>
#include <string>

class Sniffer {
public:
    Sniffer(
        int snaplen_ = BUFSIZ,
        int promisc_ = 1,
        int to_ms_ = 1000);
    ~Sniffer();

    pcap_if_t* getDevs();                           // 获取设备列表
    bool openDev();                                 // 打开设备
    bool closeDev();                                // 关闭设备
    bool setSniffer(                                // 设置嗅探器参数
        std::string devName_,
        int snaplen_ = -1,
        int promisc_ = -1,
        int to_ms_ = -1);
    bool startCapture();                            // 开始捕获数据包
    bool stopCapture();                             // 停止捕获
    bool applyFilter(const std::string& filter);    // 应用数据包过滤规则
    bool saveCapture(const std::string& filename, const struct pcap_pkthdr* header, const u_char* packet);  // 保存捕获的数据包

private:
    std::string devName;
    int snaplen;
    int promisc;
    int to_ms;

    pcap_if_t* allDevs;             // 设备列表
    pcap_t* handle;                 // 捕获句柄
    bool isCapturing;
    char errBuf[PCAP_ERRBUF_SIZE];  // 错误缓冲区
    void (*packetHandler)(u_char* user, const struct pcap_pkthdr* header, const u_char* packet);
};

#endif // SNIFFER_H
