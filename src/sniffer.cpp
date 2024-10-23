#include "sniffer.h"
#include <iostream>
#include <string.h>
#include <thread>

Sniffer::Sniffer(int snaplen_, int promisc_, int to_ms_) {
    if (snaplen_ < 0) {
        throw std::invalid_argument("snaplen can't be negative");
    }

    if (promisc_ < 0) {
        throw std::invalid_argument("promisc can't be negative");
    }

    if (to_ms_ < 0) {
        throw std::invalid_argument("to_ms can't be negative");
    }

    snaplen = snaplen_;
    promisc = promisc_;
    to_ms = to_ms_;
    allDevs = nullptr;
    handle = nullptr;
    isCapturing = false;
}

Sniffer::~Sniffer() {
    if (isCapturing) stopCapture();
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

    isCapturing = false;
    std::cout << "opened: " << devName << std::endl;
    return true;
}

void Sniffer::closeDev() {
    if (handle == nullptr) {
        std::cerr << "Device has been closed" << std::endl;
        return;
    }

    if (isCapturing) {
        stopCapture();
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
        std::cerr << "startCapture: Device has not opened" << std::endl;
        return;
    }

    if (isCapturing) {
        std::cerr << "startCapture: Device is monitoring" << std::endl;
        return;
    }

    if (packetHandler == nullptr) {
        std::cerr << "startCapture: Callback function not setted" << std::endl;
        return;
    }
    isCapturing = true;

    gettimeofday(&startTime, nullptr);

    handlerFunction = &packetHandler;

    std::cout << "capturing: " << devName << std::endl;

    pcap_loop(handle, 0, pcapCallback, nullptr);

    isCapturing = false;
    return;
}

void Sniffer::stopCapture() {
    if (handle == nullptr) {
        std::cerr << "Device is not openned" << std::endl;
        return;
    }

    if (!isCapturing) {
        std::cerr << "Device is not capturing" << std::endl;
        return;
    }

    pcap_breakloop(handle);
    isCapturing = false;
    std::cout << "stop capture: " << devName << std::endl;
    return;
}

bool Sniffer::applyFilter(const std::string& filter) {
    if (handle == nullptr) {
        std::cerr << "No devices monitored" << std::endl;
        return false;
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) < 0) {
        std::cerr << "Error compiling filter: " << pcap_geterr(handle) << std::endl;
        return false;
    }

    if (pcap_setfilter(handle, &fp) < 0) {
        pcap_freecode(&fp);
        std::cerr << "Error setting filter: " << pcap_geterr(handle) << std::endl;
        return false;
    }

    pcap_freecode(&fp);
    std::cout << "filter applied: " << filter << std::endl;
    return true;
}

bool Sniffer::saveCapture(const std::string& filename, const struct pcap_pkthdr* header, const u_char* packet) {
    if (handle == nullptr) {
        std::cerr << "No devices monitored" << std::endl;
        return false;
    }

    pcap_dumper_t* dumpfile;
    dumpfile = pcap_dump_open(handle, filename.c_str());
    if (dumpfile == nullptr) {
        std::cerr << "Error opening dump file: " << pcap_geterr(handle) << std::endl;
        return false;
    }

    pcap_dump(reinterpret_cast<u_char*>(dumpfile), header, packet);
    pcap_dump_close(dumpfile);
    std::cout << "packet saved:" << filename << std::endl;
    return true;
}