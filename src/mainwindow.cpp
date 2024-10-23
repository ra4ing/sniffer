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
    stopCaptureAction = createAction(":resources/images/stop_capture.png", "Stop Capture");
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


void MainWindow::setupConnection() {

    // exit
    connect(exitAction, &QAction::triggered, this, [this]() {
        this->close();
        });

    // searchDevice
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

    // closeConnect
    connect(closeDeviceAction, &QAction::triggered, this, [this]() {
        stopCaptureAction->setEnabled(false);
        startCaptureAction->setEnabled(false);
        });

    auto packetHandler = [this](u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
        int row = ui->packetList->rowCount();
        ui->packetList->insertRow(row);

        ParsedPacket* parsedPacket = parser->parsePacket(header, packet);
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
        };

    // startCapture
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
        });


    // stopCapture
    connect(stopCaptureAction, &QAction::triggered, this, [this]() {
        sniffer->stopCapture();
        stopCaptureAction->setEnabled(false);
        startCaptureAction->setEnabled(true);
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