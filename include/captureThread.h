#ifndef CAPTURETHREAD_H
#define CAPTURETHREAD_H

#include <QThread>
#include <pcap.h>
#include <memory>
#include "sniffer.h"

class CaptureThread : public QThread {
    Q_OBJECT
public:
        CaptureThread(
            std::shared_ptr<Sniffer> sniffer,
            std::function<void(u_char*, const pcap_pkthdr*, const u_char*)> packetHandler,
            QObject* parent = nullptr)
        : QThread(parent), sniffer(sniffer), packetHandler(packetHandler) {
    }

protected:
    void run() override {
        sniffer->startCapture(packetHandler);
    }

private:
    std::shared_ptr<Sniffer> sniffer;
    std::function<void(u_char*, const pcap_pkthdr*, const u_char*)> packetHandler;
};

#endif