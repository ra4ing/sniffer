#include "mainwindow.h"
#include "forms/ui_mainwindow.h"
#include <QMessageBox>
#include <QFileDialog>
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
    if (captureThread->isRunning()) {
        sniffer->stopCapture();
        captureThread->quit();
        captureThread->wait();
    }
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
    saveAllPacketsAction = createAction(":resources/images/save_packet.png", "Save All Packets");
    enableScrollingAction = createAction(":resources/images/enable_scrolling.png", "Disable Auto Scroll");
    exitAction = createAction(":resources/images/exit.png", "Exit");
    searchDeviceAction = createAction(":resources/images/search_device.png", "Search Device");

    closeDeviceAction = createAction(":resources/images/close_device.png", "Close Device");
    closeDeviceAction->setCheckable(true);
    closeDeviceAction->setChecked(true);
    actionGroup->addAction(closeDeviceAction);
    deviceActions.push_back(closeDeviceAction);
    
    packetListIndex = 0;
    packetHandler = [this](u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
        const struct pcap_pkthdr headerCopy = *header;
        const u_char* packetCopy = new u_char[header->caplen];
        memcpy(const_cast<u_char*>(packetCopy), packet, header->caplen);

        QMetaObject::invokeMethod(this, [this, headerCopy, packetCopy]() {
            ParsedPacket* parsedPacket = parser->parsePacket(&headerCopy, packetCopy);
            headers.push_back(new pcap_pkthdr(headerCopy));
            packets.push_back(packetCopy);
            updatePacketLists(parsedPacket, &headerCopy);
            updatePacketDetails(parsedPacket, &headerCopy);
            updateHexViews(parsedPacket, &headerCopy, packetCopy);

            pushPacketList(packetListIndex++);
            
            }, Qt::QueuedConnection);
        };
    captureThread = new CaptureThread(sniffer, packetHandler, this);
}

void MainWindow::pushPacketList(int idx) {
    int row = ui->packetList->rowCount();
    ui->packetList->insertRow(row);

    PacketListData* packetListData = packetLists.at(idx);
    ui->packetList->setItem(row, 0, packetListData->timeElapsed->clone());
    ui->packetList->setItem(row, 1, packetListData->source->clone());
    ui->packetList->setItem(row, 2, packetListData->destination->clone());
    ui->packetList->setItem(row, 3, packetListData->protocol->clone());
    ui->packetList->setItem(row, 4, packetListData->length->clone());
    ui->packetList->setItem(row, 5, packetListData->info->clone());
    if (autoScrollEnabled)
        ui->packetList->scrollToBottom();
}

void MainWindow::updatePacketLists(ParsedPacket* parsedPacket, const struct pcap_pkthdr* header) {
    if (parsedPacket == nullptr) {
        PacketListData* rowData = new PacketListData(
        new QTableWidgetItem(""),
        new QTableWidgetItem(""),
        new QTableWidgetItem(""),
        new QTableWidgetItem(""),
        new QTableWidgetItem(""),
        new QTableWidgetItem("Packet Error: header or packet")
        );

        packetLists.push_back(rowData);
        return;
    }

    timeval packetTime = header->ts;
    if (startTime.tv_sec == 0 && startTime.tv_usec == 0)
        startTime = packetTime;
    
    long secondsStart = startTime.tv_sec;
    long microsecondsStart = startTime.tv_usec;
    long secondsElapsed = packetTime.tv_sec - secondsStart;
    long microsecondsElapsed = packetTime.tv_usec - microsecondsStart;
    double totalTimeElapsed = secondsElapsed + (microsecondsElapsed / 1000000.0);
    QString formattedTime = QString::number(totalTimeElapsed, 'f', 6);

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


    PacketListData* rowData = new PacketListData(
        new QTableWidgetItem(formattedTime),
        new QTableWidgetItem(source),
        new QTableWidgetItem(destination),
        new QTableWidgetItem(protocol),
        new QTableWidgetItem(QString::number(header->caplen)),
        new QTableWidgetItem(info)
        );

    packetLists.push_back(rowData);
}

void MainWindow::updatePacketDetails(ParsedPacket* parsedPacket, const struct pcap_pkthdr* header) {
    QTreeWidgetItem* ethernetItem = new QTreeWidgetItem();
    ethernetItem->setText(0, "Ethernet");

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

            if (parsedPacket->srcPort == "80" || parsedPacket->destPort == "80") {
                QTreeWidgetItem* httpItem = new QTreeWidgetItem(tcpItem);
                httpItem->setText(0, "HTTP");
                tcpItem->addChild(new QTreeWidgetItem(QStringList() << QString::fromStdString(parsedPacket->payload)));
            }
            else if (parsedPacket->srcPort == "443" || parsedPacket->destPort == "443") {
                QTreeWidgetItem* httpsItem = new QTreeWidgetItem(tcpItem);
                httpsItem->setText(0, "HTTPS");
                httpsItem->addChild(new QTreeWidgetItem(QStringList() << QString::fromStdString(parsedPacket->payload)));
            }
                

        }
        else if (parsedPacket->protocol == IPPROTO_UDP) {
            QTreeWidgetItem* udpItem = new QTreeWidgetItem(ipItem);
            udpItem->setText(0, "User Datagram Protocol (UDP)");

            QString srcPort = QString("Source Port: %1").arg(QString::fromStdString(parsedPacket->srcPort));
            QString dstPort = QString("Destination Port: %1").arg(QString::fromStdString(parsedPacket->destPort));

            udpItem->addChild(new QTreeWidgetItem(QStringList() << srcPort));
            udpItem->addChild(new QTreeWidgetItem(QStringList() << dstPort));

            if (parsedPacket->srcPort == "53" || parsedPacket->destPort == "53") {
                QTreeWidgetItem* dnsItem = new QTreeWidgetItem(udpItem);
                dnsItem->setText(0, "DNS");
                dnsItem->addChild(new QTreeWidgetItem(QStringList() << QString::fromStdString(parsedPacket->payload)));
            }
        }
        else if (parsedPacket->protocol == IPPROTO_ICMP) {
            QTreeWidgetItem* icmpItem = new QTreeWidgetItem(ipItem);
            icmpItem->setText(0, "Internet Control Message Protocol (ICMP)");

            // 查找 ICMP 类型描述
            std::string icmpTypeDescription = icmpTypeDescriptions.count(parsedPacket->icmpType)
                ? icmpTypeDescriptions.at(parsedPacket->icmpType)
                : "Unknown Type (" + std::to_string(parsedPacket->icmpType) + ")";

            // 查找 ICMP 代码描述，根据不同类型处理不同的代码
            std::string icmpCodeDescription;
            if (parsedPacket->icmpType == 3) {  // Destination Unreachable
                icmpCodeDescription = icmpCodeDestUnreachable.count(parsedPacket->icmpCode)
                    ? icmpCodeDestUnreachable.at(parsedPacket->icmpCode)
                    : "Unknown Code (" + std::to_string(parsedPacket->icmpCode) + ")";
            }
            else if (parsedPacket->icmpType == 11) {  // Time Exceeded
                icmpCodeDescription = icmpCodeTimeExceeded.count(parsedPacket->icmpCode)
                    ? icmpCodeTimeExceeded.at(parsedPacket->icmpCode)
                    : "Unknown Code (" + std::to_string(parsedPacket->icmpCode) + ")";
            }
            else {
                icmpCodeDescription = "Code: (" + std::to_string(parsedPacket->icmpCode) + ")";
            }

            QString icmpType = QString("ICMP Type: %1").arg(QString::fromStdString(icmpTypeDescription));
            QString icmpCode = QString("ICMP Code: %1").arg(QString::fromStdString(icmpCodeDescription));

            icmpItem->addChild(new QTreeWidgetItem(QStringList() << icmpType));
            icmpItem->addChild(new QTreeWidgetItem(QStringList() << icmpCode));
        }
    }
    ethernetItems.push_back(ethernetItem);
}

void MainWindow::updateHexViews(ParsedPacket* parsedPacket, const struct pcap_pkthdr* header, const u_char* packet) {
    QString hexOutput;
    QString asciiOutput;
    QString combinedOutput;

    unsigned int length = header->caplen;
    for (unsigned int i = 0; i < length; i += 16) {
        hexOutput.append(QString("%1   ").arg(i, 4, 16, QChar('0')));

        asciiOutput.clear();

        for (unsigned int j = 0; j < 16; ++j) {
            if (i + j < length) {
                hexOutput.append(QString("%1 ").arg(packet[i + j], 2, 16, QChar('0')).toUpper());

                char ch = static_cast<char>(packet[i + j]);
                if (isprint(ch))
                    asciiOutput.append(ch);
                else
                    asciiOutput.append('.');
            }
            else
                hexOutput.append("   ");
        }

        combinedOutput.append(hexOutput + "  " + asciiOutput + "\n");
        hexOutput.clear();
    }
    hexViews.push_back(combinedOutput);
}

void MainWindow::clearLastCapture() {
    packetListIndex = 0;
    ui->packetList->clearContents();
    ui->packetList->setRowCount(0);

    for (auto ethernetItem : ethernetItems)
        delete ethernetItem;
    ethernetItems.clear();

    headers.clear();
    packets.clear();
    currentHeader = nullptr;
    currentPacket = nullptr;
    startTime = { 0, 0 };
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
        sniffer->closeDev();
        stopCaptureAction->setEnabled(false);
        startCaptureAction->setEnabled(false);
        });

    /* startCapture */
    connect(startCaptureAction, &QAction::triggered, this, [this]() {
        if (!sniffer->openDev()) {
            startCaptureAction->setEnabled(false);
            stopCaptureAction->setEnabled(false);
            QMessageBox::critical(this, "Device", "Open Device Error");
            return;
        }

        clearLastCapture();

        if (sniffer->isCapturing == 0)
            sniffer->isCapturing = -1;

        captureThread->start();

        while (sniffer->isCapturing == -1) {}

        if (sniffer->isCapturing == 0) {
            startCaptureAction->setEnabled(true);
            stopCaptureAction->setEnabled(false);
            QMessageBox::critical(this, "Capture", "Capture start Error");
            return;
        }

        startCaptureAction->setEnabled(false);
        stopCaptureAction->setEnabled(true);
        });

    /* stopCapture */
    connect(stopCaptureAction, &QAction::triggered, this, [this]() {
        sniffer->stopCapture();
        stopCaptureAction->setEnabled(false);
        startCaptureAction->setEnabled(true);
        });

    /* packetList */
    connect(ui->packetList, &QTableWidget::itemSelectionChanged, this, [this]() {
        int currentRow = ui->packetList->currentRow();
        if (currentRow >= 0 && currentRow < ethernetItems.size()) {
            ui->packetDetails->clear();
            ui->packetDetails->addTopLevelItem(ethernetItems[currentRow]->clone());
            ui->packetDetails->expandAll();

            ui->hexView->clear();
            ui->hexView->setPlainText(hexViews[currentRow]);

            currentHeader = headers[currentRow];
            currentPacket = packets[currentRow];

            autoScrollEnabled = false;
            enableScrollingAction->setText("Enable Auto Scroll");
        }
        });

    /* scrolling */
    autoScrollEnabled = true;
    connect(enableScrollingAction, &QAction::triggered, this, [this]() {
        autoScrollEnabled = !autoScrollEnabled;
        enableScrollingAction->setText(autoScrollEnabled ? "Disable Auto Scroll" : "Enable Auto Scroll");
        });

    /* savePacket */
    connect(savePacketAction, &QAction::triggered, this, [this]() {
        if (currentHeader == nullptr || currentPacket == nullptr) {
            QMessageBox::information(this, "Failed save", "No packet selected");
            return;
        }

        QString fileName = QFileDialog::getSaveFileName(this, tr("Save Packet"), "", tr("PCAP Files (*.pcap)"));
        if (fileName.isEmpty())
            return;

        if (sniffer->savePacket(fileName.toStdString(), currentHeader, currentPacket) == -1) {
            QMessageBox::critical(this, "Failed save", "Save packets error");
            return;
        }
        });

    /* saveAllPackets */
    connect(saveAllPacketsAction, &QAction::triggered, this, [this]() {
        if (headers.empty() || packets.empty()) {
            QMessageBox::information(this, "Failed save", "No packets");
            return;
        }

        QString fileName = QFileDialog::getSaveFileName(this, tr("Save All Packets"), "", tr("PCAP Files (*.pcap)"));
        if (fileName.isEmpty())
            return;

        
        if (sniffer->saveAllPackets(fileName.toStdString(), headers, packets) == -1) {
            QMessageBox::critical(this, "Failed save", "Save packets error");
            return;
        }
        });

    /* openPacket */
    connect(openPacketAction, &QAction::triggered, this, [this]() {
        QString fileName = QFileDialog::getOpenFileName(this, tr("Open Packet"), "", tr("PCAP Files (*.pcap)"));
        if (fileName.isEmpty())
            return;

        closeDeviceAction->trigger();
        clearLastCapture();

        if (sniffer->openPacket(fileName.toStdString(), packetHandler) == false) {
            QMessageBox::critical(this, "Failed open", "Open Packet failed");
            return;
        }

        });

    /* applyFilter */
    connect(ui->applyFilterButton, &QPushButton::clicked, this, [this]() {
        QString filterText = ui->filterInput->text();

        int result = sniffer->applyFilter(filterText.toStdString());
        if (result == -1) {
            QMessageBox::critical(this, "Filter", "No devices opened");
            return;
        }
        else if (result == -2) {
            ui->filterInput->setStyleSheet("color: red;");
            QMessageBox::warning(this, "Filter", "Error compiling filter");
            return;
        }
        else if (result == -3) {
            QMessageBox::critical(this, "Filter", "Error setting filter");
            return;
        }

        ui->filterInput->setStyleSheet("color: black;");

        if (ui->savedFilters->findText(filterText) == -1)
            ui->savedFilters->addItem(filterText);
        });

    /* afterApplyFilter */
    connect(ui->afterApplyFilterButton, &QPushButton::clicked, this, [this]() {
        QString filterText = ui->afterFilterInput->text();

        filteredIndex.clear();
        packetListIndex = 0;
        ui->packetList->clearContents();
        ui->packetList->setRowCount(0);

        int result = sniffer->filterCapturedPackets(filterText.toStdString(),
            headers,
            packets,
            filteredIndex);

        if (result == -1) {
            QMessageBox::critical(this, "Filter", "No devices opened");
            return;
        }
        else if (result == -2) {
            ui->afterFilterInput->setStyleSheet("color: red;");
            QMessageBox::warning(this, "Filter", "Error compiling filter");
            return;
        }

        ui->afterFilterInput->setStyleSheet("color: black;");
        if (ui->afterSavedFilter->findText(filterText) == -1)
            ui->afterSavedFilter->addItem(filterText);


        for (int index : filteredIndex) {
            std::cout << index << std::endl;
            pushPacketList(index);
        }

        });
}

void MainWindow::setupMenu() {
    fileMenu = ui->menubar->addMenu("File");
    deviceMenu = ui->menubar->addMenu("Device");
    analysisMenu = ui->menubar->addMenu("Analysis");
    statisticsMenu = ui->menubar->addMenu("Statistics");

    fileMenu->addAction(startCaptureAction);
    fileMenu->addAction(stopCaptureAction);
    fileMenu->addAction(exitAction);

    deviceMenu->addAction(searchDeviceAction);
    deviceMenu->addAction(closeDeviceAction);
}


void MainWindow::setupToolBar() {
    ui->toolBar->addAction(startCaptureAction);
    ui->toolBar->addAction(stopCaptureAction);
    ui->toolBar->addAction(openPacketAction);
    ui->toolBar->addAction(savePacketAction);
    ui->toolBar->addAction(saveAllPacketsAction);
    ui->toolBar->addAction(enableScrollingAction);
}

void MainWindow::setupDeviceBar() {
    ui->deviceBar->clear();
    ui->deviceBar->addAction(searchDeviceAction);
    ui->deviceBar->addAction(closeDeviceAction);
    ui->deviceBar->addActions(deviceActions);
}

void MainWindow::connectDeviceAction(pcap_if_t* dev) {
    QAction* deviceAction = new QAction(QIcon(":resources/images/device.png"), dev->name, this);
    deviceAction->setCheckable(true);
    actionGroup->addAction(deviceAction);
    deviceActions.push_back(deviceAction);

    QString toolTipText = dev->description ? QString("%1: %2").arg(dev->name).arg(dev->description)
        : QString("%1: ").arg(dev->name);
    deviceAction->setToolTip(toolTipText);

    connect(deviceAction, &QAction::toggled, this, [&, dev, this](bool checked) {
        ui->filterInput->clear();
        ui->afterFilterInput->clear();
        if (checked) {
            ui->filterInput->clear();
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