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

    setupAction();
    setupConnection();
    setupMenu();
    setupToolBar();
    setupDeviceBar();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::setupAction() {
    startCaptureAction = new QAction(QIcon(":resources/images/start_capture.png"), "Start Capture", this);
    stopCaptureAction = new QAction(QIcon(":resources/images/stop_capture.png"), "Stop Capture", this);
    openPacketAction = new QAction(QIcon(":resources/images/open_packet.png"), "Open Packet", this);
    savePacketAction = new QAction(QIcon(":resources/images/save_packet.png"), "Save Packet", this);
    enableScrollingAction = new QAction(QIcon(":resources/images/enable_scrolling.png"), "Enable Packet", this);
    exitAction = new QAction(QIcon(":resources/images/exit.png"), "Exit", this);
    searchDeviceAction = new QAction(QIcon(":resources/images/search_device.png"), "Search Device", this);

}

// void MainWindow::packetHandler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
//     ParsedPacket* parsedPacket = parser.parsePacket(header, packet);

// }

void MainWindow::setupConnection() {

    // searchDevice
    connect(searchDeviceAction, &QAction::triggered, this, [this]() {
        deviceActions.clear();
        pcap_if_t* alldevs = sniffer.getDevs();
        for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next)
            this->connectDeviceAction(dev);

        this->setupDeviceBar();
        });


    auto packetHandler = [this](u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
        ParsedPacket* parsedPacket = parser.parsePacket(header, packet);

        CaptureContext* context = reinterpret_cast<CaptureContext*>(user);
        timeval packetTime = header->ts;
        long secondsElapsed = packetTime.tv_sec - context->startTime.tv_sec;
        // long microsecondsElapsed = packetTime.tv_usec - context->startTime.tv_usec;

        int row = ui->packetList->rowCount();
        ui->packetList->insertRow(row);
        ui->packetList->setItem(row, 0, new QTableWidgetItem(QString::number(row + 1)));
        ui->packetList->setItem(row, 1, new QTableWidgetItem(QString::number(secondsElapsed)));

        std::cout << secondsElapsed << std::endl;
        std::cout << header->caplen << std::endl;
        QString source, destination, protocol;
        if (parsedPacket->protocol == IPPROTO_TCP ) {
            source = QString::fromStdString(parsedPacket->srcIP);
            destination = QString::fromStdString(parsedPacket->destIP);
            protocol = "TCP";
        } else if (parsedPacket->protocol == IPPROTO_UDP) {
            source = QString::fromStdString(parsedPacket->srcIP);
            destination = QString::fromStdString(parsedPacket->destIP);
            protocol = "UDP";
        } else {
            source = QString::fromStdString(parsedPacket->srcMAC);
            destination = QString::fromStdString(parsedPacket->destMAC);
            protocol = "Other";
        }

        ui->packetList->setItem(row, 2, new QTableWidgetItem(source));
        ui->packetList->setItem(row, 3, new QTableWidgetItem(destination));
        ui->packetList->setItem(row, 4, new QTableWidgetItem(protocol));
        ui->packetList->setItem(row, 5, new QTableWidgetItem(QString::number(header->caplen)));
        
    };

    // startCapture
    connect(startCaptureAction, &QAction::triggered, this, [this, packetHandler]() {
        std::thread captureThread([this, packetHandler]() {
            sniffer.startCapture(packetHandler);
        });
        captureThread.detach();
        });

    // stopCapture
    connect(stopCaptureAction, &QAction::triggered, this, [this]() {
        sniffer.stopCapture();
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
    ui->deviceBar->setStyleSheet("QToolBar { min-width: 500px; }");
    ui->deviceBar->clear();
    ui->deviceBar->addAction(searchDeviceAction);
    ui->deviceBar->addActions(deviceActions);
}

void MainWindow::connectDeviceAction(pcap_if_t* dev) {
    QAction* newAction = new QAction(QIcon(":resources/images/device.png"), dev->name, this);
    newAction->setCheckable(true);
    QString toolTipText = dev->description ? QString("%1: %2").arg(dev->name).arg(dev->description)
        : QString("%1: ").arg(dev->name);
    newAction->setToolTip(toolTipText);

    connect(newAction, &QAction::toggled, this, [&, dev](bool checked) {
        if (checked) {
            sniffer.closeDev();
            sniffer.setSniffer(dev->name);
            sniffer.openDev();
        }
        else
            sniffer.closeDev();

        });
    deviceActions.push_back(newAction);
}