#include "sniffer.h"
#include <iostream>
#include <string.h>
#include <thread>

Sniffer::Sniffer(int snaplen_, int promisc_, int to_ms_) {
    if (snaplen_ < 0)
        throw std::invalid_argument("snaplen can't be negative");

    if (promisc_ < 0)
        throw std::invalid_argument("promisc can't be negative");

    if (to_ms_ < 0)
        throw std::invalid_argument("to_ms can't be negative");

    snaplen = snaplen_;
    promisc = promisc_;
    to_ms = to_ms_;
    allDevs = nullptr;
    handle = nullptr;
    isCapturing = 0;
}

Sniffer::~Sniffer() {
    if (isCapturing == 1) stopCapture();
    if (handle != nullptr) closeDev();
    if (allDevs != nullptr) pcap_freealldevs(allDevs);
}

bool Sniffer::setSniffer(
    std::string devName_,
    int snaplen_,
    int promisc_,
    int to_ms_) {

    if (allDevs == nullptr) {
        std::cerr << "No device found" << std::endl;
        return false;
    }

    bool haveDev = false;
    for (pcap_if_t* dev = allDevs; dev != nullptr; dev = dev->next) {
        if (!strcmp(dev->name, devName_.c_str())) {
            haveDev = true;
            break;
        }
    }

    if (!haveDev) {
        std::cerr << "No device named: " << devName_ << std::endl;
        return false;
    }

    if (handle != nullptr && devName_.compare(devName)) {
        std::cerr << "One device has beening opened: " << devName << std::endl;
        return false;
    }

    devName = (devName_.empty()) ? devName : devName_;
    snaplen = (snaplen_ < 0) ? snaplen : snaplen_;
    promisc = (promisc_ < 0) ? promisc : promisc_;
    to_ms = (to_ms_ < 0) ? to_ms : to_ms_;
    return true;
}

pcap_if_t* Sniffer::getDevs() {
    if (allDevs == nullptr) {
        pcap_freealldevs(allDevs);
    }

    if (pcap_findalldevs(&allDevs, errBuf) < 0) {
        std::cerr << "Error finding devices: " << errBuf << std::endl;
        return nullptr;
    }

    return allDevs;
}

bool Sniffer::openDev() {
    if (handle != nullptr) {
        std::cout << "Device has beening opened: " << devName << std::endl;
        return true;
    }

    handle = pcap_open_live(devName.c_str(), snaplen, promisc, to_ms, errBuf);
    if (handle == nullptr) {
        std::cerr << "openDev: Error opening device: " << errBuf << std::endl;
        return false;
    }

    isCapturing = 0;
    std::cout << "opened: " << devName << std::endl;
    return true;
}

void Sniffer::closeDev() {
    if (isCapturing == 1)
        stopCapture();

    if (handle == nullptr) {
        return;
    }

    pcap_close(handle);
    devName = "";
    handle = nullptr;
    std::cout << "closed: " << devName << std::endl;
}

static std::function<void(u_char* args, const struct pcap_pkthdr* header, const u_char* packet)>* handlerFunction;
static void pcapCallback(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    (*handlerFunction)(user, header, packet);
}

void Sniffer::startCapture(std::function<void(u_char* user, const struct pcap_pkthdr* header, const u_char* packet)> packetHandler) {
    if (handle == nullptr) {
        isCapturing = 0;
        std::cerr << "startCapture: Device has not opened" << std::endl;
        return;
    }

    if (isCapturing == 1) {
        std::cerr << "startCapture: Device is monitoring" << std::endl;
        return;
    }

    if (packetHandler == nullptr) {
        isCapturing = 0;
        std::cerr << "startCapture: Callback function not setted" << std::endl;
        return;
    }
    isCapturing = 1;

    // gettimeofday(&startTime, nullptr);

    handlerFunction = &packetHandler;

    std::cout << "capturing: " << devName << std::endl;

    pcap_loop(handle, 0, pcapCallback, nullptr);

    isCapturing = 0;
    return;
}

void Sniffer::stopCapture() {
    if (handle == nullptr) {
        return;
    }

    if (isCapturing == 0) {
        return;
    }

    pcap_breakloop(handle);
    isCapturing = 0;
    std::cout << "stop capture: " << devName << std::endl;
    return;
}

int Sniffer::applyFilter(const std::string& filter) {
    if (handle == nullptr) {
        std::cerr << "No devices opened" << std::endl;
        return -1;
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) < 0) {
        std::cerr << "Error compiling filter: " << pcap_geterr(handle) << std::endl;
        return -2;
    }

    if (pcap_setfilter(handle, &fp) < 0) {
        pcap_freecode(&fp);
        std::cerr << "Error setting filter: " << pcap_geterr(handle) << std::endl;
        return -3;
    }

    pcap_freecode(&fp);
    std::cout << "filter applied: " << filter << std::endl;
    return 0;
}

int Sniffer::filterCapturedPackets(const std::string& filter,
    std::vector<const pcap_pkthdr*>& headers,
    std::vector<const u_char*>& packets,
    std::vector<int>& filteredIndex) {

    if (handle == nullptr) {
        std::cerr << "No devices opened" << std::endl;
        return -1;
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) < 0) {
        std::cerr << "Error compiling filter: " << pcap_geterr(handle) << std::endl;
        return -2;
    }

    for (size_t i = 0; i < headers.size(); ++i) {
        const struct pcap_pkthdr* header = headers[i];
        const u_char* packet = packets[i];

        if (pcap_offline_filter(&fp, header, packet))
            filteredIndex.push_back(i);
    
    }

    pcap_freecode(&fp);
    return true;
}

int Sniffer::savePacket(const std::string& filename, const struct pcap_pkthdr* header, const u_char* packet) {
    if (header == nullptr || packet == nullptr) {
        std::cerr << "Header or Packet can't be nullptr" << std::endl;
        return -1;
    }

    pcap_t* tempHandle = nullptr;
    if (handle == nullptr) {

        char errbuf[PCAP_ERRBUF_SIZE];
        tempHandle = pcap_open_dead(DLT_EN10MB, 65535);
        if (tempHandle == nullptr) {
            std::cerr << "Error creating offline pcap handle" << std::endl;
            return -1;
        }
    }

    pcap_t* activeHandle = (handle != nullptr) ? handle : tempHandle;  // 使用现有句柄或离线句柄

    pcap_dumper_t* dumpfile;
    dumpfile = pcap_dump_open(activeHandle, filename.c_str());
    if (dumpfile == nullptr) {
        std::cerr << "Error opening dump file: " << pcap_geterr(activeHandle) << std::endl;

        if (tempHandle != nullptr)
            pcap_close(tempHandle);
        return -1;
    }

    pcap_dump(reinterpret_cast<u_char*>(dumpfile), header, packet);
    pcap_dump_close(dumpfile);
    if (tempHandle != nullptr)
        pcap_close(tempHandle);
    
    std::cout << "packet saved:" << filename << std::endl;
    return 0;
}

int Sniffer::saveAllPackets(
    const std::string& filename,
    const std::vector<const pcap_pkthdr*>& headers,
    const std::vector<const u_char*>& packets) {

    if (headers.size() != packets.size()) {
        std::cerr << "Headers and packets vectors must be the same size." << std::endl;
        return -1;
    }

    pcap_t* tempHandle = nullptr;
    if (handle == nullptr) {
        char errbuf[PCAP_ERRBUF_SIZE];
        tempHandle = pcap_open_dead(DLT_EN10MB, 65535);
        if (tempHandle == nullptr) {
            std::cerr << "Error creating offline pcap handle" << std::endl;
            return -1;
        }
    }

    pcap_t* activeHandle = (handle != nullptr) ? handle : tempHandle;
    pcap_dumper_t* dumpfile = pcap_dump_open(activeHandle, filename.c_str());
    if (dumpfile == nullptr) {
        std::cerr << "Error opening dump file: " << pcap_geterr(activeHandle) << std::endl;
        if (tempHandle != nullptr)
            pcap_close(tempHandle);
        return -1;
    }

    for (size_t i = 0; i < headers.size(); ++i) {
        pcap_dump(reinterpret_cast<u_char*>(dumpfile), headers[i], packets[i]);
    }

    pcap_dump_close(dumpfile);
    if (tempHandle != nullptr)
        pcap_close(tempHandle);

    std::cout << "All packets saved to: " << filename << std::endl;
    return 0;

}

bool Sniffer::openPacket(const std::string& filename, std::function<void(u_char* user, const struct pcap_pkthdr* header, const u_char* packet)> packetHandler) {
    if (packetHandler == nullptr) {
        std::cerr << "startCapture: Callback function not setted" << std::endl;
        return false;
    }

    if (isCapturing == 1)
        stopCapture();

    if (handle != nullptr)
        closeDev();

    pcap_t* pcapFileHandle = pcap_open_offline(filename.c_str(), errBuf);
    if (pcapFileHandle == nullptr) {
        std::cerr << "openDev: Error opening device: " << errBuf << std::endl;
        return false;
    }
    // gettimeofday(&startTime, nullptr);

    handlerFunction = &packetHandler;
    if (pcap_loop(pcapFileHandle, 0, pcapCallback, nullptr) == -1) {
        std::cerr << "Error reading packet: " << pcap_geterr(pcapFileHandle) << std::endl;
        pcap_close(pcapFileHandle);
        return false;
    }
    pcap_close(pcapFileHandle);
    return true;
}

