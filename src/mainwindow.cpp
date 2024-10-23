#include "mainwindow.h"
#include "forms/ui_mainwindow.h"
#include "sniffer.h"
#include <QMessageBox>
#include <iostream>
#include <thread>

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    actionGroup = std::make_shared<QActionGroup>(this);
    actionGroup->setExclusive(true);

    sniffer = std::make_shared<Sniffer>();
    parser = std::make_shared<PacketParser>();

    setupPacketList();
    setupAction();
    setupConnection();
    setupMenu();
    setupToolBar();
    setupDeviceBar();
}

MainWindow::~MainWindow() {
    sniffer->stopCapture();
    sniffer->closeDev();
    for (auto ethernetItem : ethernetItems)
            delete ethernetItem;
    delete ui;
}

void MainWindow::setupPacketList() {
    ui->packetList->setColumnWidth(0, 100);  // Time
    ui->packetList->setColumnWidth(1, 150);  // Source
    ui->packetList->setColumnWidth(2, 150);  // Destination
    ui->packetList->setColumnWidth(3, 100);  // Protocol
    ui->packetList->setColumnWidth(4, 80);   // Length
    ui->packetList->setColumnWidth(5, 300);  // Info
}

void MainWindow::setupAction() {
    auto createAction = [this](const QString& iconPath, const QString& text) {
        return new QAction(QIcon(iconPath), text, this);
        };

    startCaptureAction = createAction(":resources/images/start_capture.png", "Start Capture");
    startCaptureAction->setEnabled(false);

    stopCaptureAction = createAction(":resources/images/stop_capture.png", "Stop Capture");
    stopCaptureAction->setEnabled(false);

    openPacketAction = createAction(":resources/images/open_packet.png", "Open Packet");
    savePacketAction = createAction(":resources/images/save_packet.png", "Save Packet");
    enableScrollingAction = createAction(":resources/images/enable_scrolling.png", "Enable Scrolling");
    exitAction = createAction(":resources/images/exit.png", "Exit");
    searchDeviceAction = createAction(":resources/images/search_device.png", "Search Device");

    closeDeviceAction = createAction(":resources/images/close_device.png", "Close Device");
    closeDeviceAction->setCheckable(true);
    closeDeviceAction->setChecked(true);
    actionGroup->addAction(closeDeviceAction);
    deviceActions.push_back(closeDeviceAction);
}

void MainWindow::updatePacketList(ParsedPacket* parsedPacket, const struct pcap_pkthdr* header) {
    int row = ui->packetList->rowCount();
    ui->packetList->insertRow(row);

    if (parsedPacket == nullptr) {
        ui->packetList->setItem(row, 5, new QTableWidgetItem("Header or Packet Error: nullptr"));
        return;
    }

    timeval packetTime = header->ts;
    long secondsStart = sniffer->startTime.tv_sec;
    long microsecondsStart = sniffer->startTime.tv_usec;
    long secondsElapsed = packetTime.tv_sec - secondsStart;
    long microsecondsElapsed = packetTime.tv_usec - microsecondsStart;
    double totalTimeElapsed = secondsElapsed + (microsecondsElapsed / 1000000.0);
    QString formattedTime = QString::number(totalTimeElapsed, 'f', 6);

    ui->packetList->setItem(row, 0, new QTableWidgetItem(formattedTime));

    QString source, destination, protocol, info;
    if (parsedPacket->protocol == IPPROTO_TCP) {
        source = QString::fromStdString(parsedPacket->srcIP);
        destination = QString::fromStdString(parsedPacket->destIP);
        protocol = "TCP";
        info = QString("Src Port: %1, Dst Port: %2, Flags: 0x%3")
            .arg(QString::fromStdString(parsedPacket->srcPort))
            .arg(QString::fromStdString(parsedPacket->destPort))
            .arg(QString::number(parsedPacket->tcpFlags, 16));  // TCP flags in hex
    }
    else if (parsedPacket->protocol == IPPROTO_UDP) {
        source = QString::fromStdString(parsedPacket->srcIP);
        destination = QString::fromStdString(parsedPacket->destIP);
        protocol = "UDP";
        info = QString("Src Port: %1, Dst Port: %2")
            .arg(QString::fromStdString(parsedPacket->srcPort))
            .arg(QString::fromStdString(parsedPacket->destPort));
    }
    else {
        source = QString::fromStdString(parsedPacket->srcMAC);
        destination = QString::fromStdString(parsedPacket->destMAC);
        protocol = "Other";
    }

    ui->packetList->setItem(row, 1, new QTableWidgetItem(source));
    ui->packetList->setItem(row, 2, new QTableWidgetItem(destination));
    ui->packetList->setItem(row, 3, new QTableWidgetItem(protocol));
    ui->packetList->setItem(row, 4, new QTableWidgetItem(QString::number(header->caplen)));
    ui->packetList->setItem(row, 5, new QTableWidgetItem(info));
}

void MainWindow::updatePacketDetail(ParsedPacket* parsedPacket, const struct pcap_pkthdr* header) {
    QTreeWidgetItem* ethernetItem = new QTreeWidgetItem();
    ethernetItem->setText(0, "Ethernet II");

    // Ethernet
    QString srcMAC = QString("Source MAC: %1").arg(QString::fromStdString(parsedPacket->srcMAC));
    QString dstMAC = QString("Destination MAC: %1").arg(QString::fromStdString(parsedPacket->destMAC));
    ethernetItem->addChild(new QTreeWidgetItem(QStringList() << srcMAC));
    ethernetItem->addChild(new QTreeWidgetItem(QStringList() << dstMAC));

    if (parsedPacket->protocol == IPPROTO_TCP || IPPROTO_UDP || IPPROTO_ICMP) {
        QTreeWidgetItem* ipItem = new QTreeWidgetItem(ethernetItem);
        ipItem->setText(0, "Internet Protocol (IP)");

        QString srcIP = QString("Source IP: %1").arg(QString::fromStdString(parsedPacket->srcIP));
        QString dstIP = QString("Destination IP: %1").arg(QString::fromStdString(parsedPacket->destIP));
        QString ttl = QString("TTL: %1").arg(parsedPacket->ttl);
        QString totalLength = QString("Total Length: %1 bytes").arg(parsedPacket->totalLength);
        ipItem->addChild(new QTreeWidgetItem(QStringList() << srcIP));
        ipItem->addChild(new QTreeWidgetItem(QStringList() << dstIP));
        ipItem->addChild(new QTreeWidgetItem(QStringList() << ttl));
        ipItem->addChild(new QTreeWidgetItem(QStringList() << totalLength));


        if (parsedPacket->protocol == IPPROTO_TCP) {
            QTreeWidgetItem* tcpItem = new QTreeWidgetItem(ipItem);
            tcpItem->setText(0, "Transmission Control Protocol (TCP)");

            QString srcPort = QString("Source Port: %1").arg(QString::fromStdString(parsedPacket->srcPort));
            QString dstPort = QString("Destination Port: %1").arg(QString::fromStdString(parsedPacket->destPort));
            QString seqNumber = QString("Sequence Number: %1").arg(parsedPacket->seqNumber);
            QString ackNumber = QString("Acknowledgment Number: %1").arg(parsedPacket->ackNumber);

            QString flagsDescription;
            if (parsedPacket->tcpFlags & TH_FIN)  flagsDescription.append("FIN ");
            if (parsedPacket->tcpFlags & TH_SYN)  flagsDescription.append("SYN ");
            if (parsedPacket->tcpFlags & TH_RST)  flagsDescription.append("RST ");
            if (parsedPacket->tcpFlags & TH_PUSH) flagsDescription.append("PSH ");
            if (parsedPacket->tcpFlags & TH_ACK)  flagsDescription.append("ACK ");
            if (parsedPacket->tcpFlags & TH_URG)  flagsDescription.append("URG ");
            
            if (flagsDescription.isEmpty()) {
                flagsDescription = "NONE";
            }
            QString tcpFlags = QString("TCP Flags: %1 (0x%2)").arg(flagsDescription.trimmed()).arg(QString::number(parsedPacket->tcpFlags, 16));

            QString windowSize = QString("Window Size: %1").arg(parsedPacket->windowSize);

            tcpItem->addChild(new QTreeWidgetItem(QStringList() << srcPort));
            tcpItem->addChild(new QTreeWidgetItem(QStringList() << dstPort));
            tcpItem->addChild(new QTreeWidgetItem(QStringList() << seqNumber));
            tcpItem->addChild(new QTreeWidgetItem(QStringList() << ackNumber));
            tcpItem->addChild(new QTreeWidgetItem(QStringList() << tcpFlags));
            tcpItem->addChild(new QTreeWidgetItem(QStringList() << windowSize));
        } else if (parsedPacket->protocol == IPPROTO_UDP) {
            QTreeWidgetItem* udpItem = new QTreeWidgetItem(ipItem);
            udpItem->setText(0, "User Datagram Protocol (UDP)");

            QString srcPort = QString("Source Port: %1").arg(QString::fromStdString(parsedPacket->srcPort));
            QString dstPort = QString("Destination Port: %1").arg(QString::fromStdString(parsedPacket->destPort));

            udpItem->addChild(new QTreeWidgetItem(QStringList() << srcPort));
            udpItem->addChild(new QTreeWidgetItem(QStringList() << dstPort));
        } else if (parsedPacket->protocol == IPPROTO_ICMP) {
            QTreeWidgetItem* icmpItem = new QTreeWidgetItem(ipItem);
            icmpItem->setText(0, "Internet Control Message Protocol (ICMP)");

            QString icmpType = QString("ICMP Type: %1").arg(parsedPacket->icmpType);
            QString icmpCode = QString("ICMP Code: %1").arg(parsedPacket->icmpCode);

            icmpItem->addChild(new QTreeWidgetItem(QStringList() << icmpType));
            icmpItem->addChild(new QTreeWidgetItem(QStringList() << icmpCode));
        }
    }
    ethernetItems.push_back(ethernetItem);
}

void MainWindow::setupConnection() {

    /* exit */
    connect(exitAction, &QAction::triggered, this, [this]() {
        this->close();
        });

    /* searchDevice */
    connect(searchDeviceAction, &QAction::triggered, this, [this]() {
        // clear deviceBar
        for (int i = 1; i < deviceActions.size(); ++i) {
            QAction* action = deviceActions[i];
            actionGroup->removeAction(action);
        }
        deviceActions.clear();

        // add device action
        pcap_if_t* allDevs = sniffer->getDevs();
        if (allDevs == nullptr) {
            QMessageBox::critical(this, "Device", "Find Device Error");
            exitAction->triggered();
            return;
        }
        for (pcap_if_t* dev = allDevs; dev != nullptr; dev = dev->next)
            this->connectDeviceAction(dev);

        // add to deviceBar
        this->setupDeviceBar();
        });

    /* closeConnect */
    connect(closeDeviceAction, &QAction::triggered, this, [this]() {
        stopCaptureAction->setEnabled(false);
        startCaptureAction->setEnabled(false);
        });

    auto packetHandler = [this](u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
        ParsedPacket* parsedPacket = parser->parsePacket(header, packet);

        updatePacketList(parsedPacket, header);
        updatePacketDetail(parsedPacket, header);
        };

    /* startCapture */
    connect(startCaptureAction, &QAction::triggered, this, [this, packetHandler]() {
        if (!sniffer->openDev()) {
            startCaptureAction->setEnabled(false);
            stopCaptureAction->setEnabled(false);
            QMessageBox::critical(this, "Device", "Open Device Error");
            return;
        }

        std::thread captureThread([this, packetHandler]() {
            sniffer->startCapture(packetHandler);
            });
        captureThread.detach();

        const int maxRetries = 10;  // 最大重试次数
        const int waitDuration = 100;  // 每次等待100ms
        int retries = 0;

        while (!sniffer->isCapturing && retries < maxRetries) {
            std::this_thread::sleep_for(std::chrono::milliseconds(waitDuration));
            retries++;
        }

        if (!sniffer->isCapturing) {
            startCaptureAction->setEnabled(true);
            stopCaptureAction->setEnabled(false);
            QMessageBox::critical(this, "Capture", "Capture start Error");
            return;
        }

        startCaptureAction->setEnabled(false);
        stopCaptureAction->setEnabled(true);
        ui->packetList->clearContents();
        ui->packetList->setRowCount(0);
        for (auto ethernetItem : ethernetItems)
            delete ethernetItem;
        ethernetItems.clear();
        });


    /* stopCapture */
    connect(stopCaptureAction, &QAction::triggered, this, [this]() {
        sniffer->stopCapture();
        stopCaptureAction->setEnabled(false);
        startCaptureAction->setEnabled(true);
        });

    /* packetList */
    connect(ui->packetList, &QTableWidget::itemSelectionChanged, this, [this]() {
        int currentRow = ui->packetList->currentRow() - 1;
        if (currentRow >= 0 && currentRow < ethernetItems.size()) {
            ui->packetDetails->clear();
            ui->packetDetails->addTopLevelItem(ethernetItems[currentRow]->clone());
            ui->packetDetails->expandAll();
        }
        });
}

void MainWindow::setupMenu() {
    fileMenu = ui->menubar->addMenu("File");
    deviceMenu = ui->menubar->addMenu("Device");
    analysisMenu = ui->menubar->addMenu("Analysis");
    statisticsMenu = ui->menubar->addMenu("Statistics");
    helpMenu = ui->menubar->addMenu("Help");

    fileMenu->addAction(startCaptureAction);
    fileMenu->addAction(exitAction);
}


void MainWindow::setupToolBar() {
    ui->toolBar->addAction(startCaptureAction);
    ui->toolBar->addAction(stopCaptureAction);
    ui->toolBar->addAction(openPacketAction);
    ui->toolBar->addAction(savePacketAction);
    ui->toolBar->addAction(enableScrollingAction);
}

void MainWindow::setupDeviceBar() {
    ui->deviceBar->clear();
    ui->deviceBar->addAction(searchDeviceAction);
    ui->deviceBar->addAction(closeDeviceAction);
    ui->deviceBar->addActions(deviceActions);
}

void MainWindow::connectDeviceAction(pcap_if_t* dev) {
    QAction* newAction = new QAction(QIcon(":resources/images/device.png"), dev->name, this);
    newAction->setCheckable(true);
    actionGroup->addAction(newAction);
    deviceActions.push_back(newAction);

    QString toolTipText = dev->description ? QString("%1: %2").arg(dev->name).arg(dev->description)
        : QString("%1: ").arg(dev->name);
    newAction->setToolTip(toolTipText);

    connect(newAction, &QAction::toggled, this, [&, dev, this](bool checked) {
        if (checked) {
            if (!sniffer->setSniffer(dev->name)) {
                stopCaptureAction->setEnabled(false);
                startCaptureAction->setEnabled(false);
                QMessageBox::critical(this, "Device", "Set Device Error");
                return;
            }
            if (!sniffer->openDev()) {
                stopCaptureAction->setEnabled(false);
                startCaptureAction->setEnabled(false);
                QMessageBox::critical(this, "Device", "Open Device Error");
                return;
            }
            stopCaptureAction->setEnabled(false);
            startCaptureAction->setEnabled(true);
        }
        else {
            sniffer->stopCapture();
            sniffer->closeDev();
        }

        });

}