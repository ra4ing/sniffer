#include <pcap.h>
#include <iostream>

void pcap_findalldevs_test() {
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    // 获取所有设备
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return;
    }

    // 遍历设备列表
    for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next) {
        std::cout << "Device: " << dev->name << std::endl;
        if (dev->description)
            std::cout << "Description: " << dev->description << std::endl;
        else
            std::cout << "No description available." << std::endl;
        std::cout << std::endl;
    }

    // 释放设备列表
    pcap_freealldevs(alldevs);
    return;
}

void pcap_open_live_test() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    // 打开设备 eth0
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        return;
    }

    std::cout << "Device opened successfully!" << std::endl;

    // 捕获完毕后关闭
    pcap_close(handle);
    return;
}

void pcap_compile_test() {
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

    // 打开网络接口
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        return;
    }

    // 编译过滤表达式
    const char* filter_exp = "tcp";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Error compiling filter: " << pcap_geterr(handle) << std::endl;
        return;
    }

    // 应用过滤器
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Error setting filter: " << pcap_geterr(handle) << std::endl;
        return;
    }

    std::cout << "Filter applied successfully!" << std::endl;

    // 清理过滤器
    pcap_freecode(&fp);
    pcap_close(handle);
    return;
}

void packetHandler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    std::cout << "Captured packet with length: " << header->len << std::endl;
}

void pcap_loop_test() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    // 打开设备
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        return;
    }

    // 开始捕获数据包，捕获 10 个数据包
    pcap_loop(handle, 10, packetHandler, nullptr);
    // pcap_breakloop(handle);

    // 关闭设备
    pcap_close(handle);
    return;
}

void pcap_dump_test() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    pcap_dumper_t* dumpfile;

    // 打开网络设备
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        return;
    }

    // 打开保存数据包的文件
    dumpfile = pcap_dump_open(handle, "captured_packets.pcap");
    if (dumpfile == nullptr) {
        std::cerr << "Error opening dump file: " << pcap_geterr(handle) << std::endl;
        return;
    }

    // 捕获数据包并保存到文件
    pcap_loop(handle, 10, [](u_char* dumpfile, const struct pcap_pkthdr* header, const u_char* packet) {
        pcap_dump(dumpfile, header, packet);
    }, reinterpret_cast<u_char*>(dumpfile));

    // 关闭保存文件和捕获设备
    pcap_dump_close(dumpfile);
    pcap_close(handle);
    return;
}

int main() {
    pcap_findalldevs_test();
    // pcap_open_live_test();
    // pcap_compile_test();
    // pcap_loop_test();
    // pcap_dump_test();
    return 0;
}

