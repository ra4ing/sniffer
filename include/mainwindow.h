#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "sniffer.h"
#include "parser.h"
#include "captureThread.h"
#include <QMainWindow>
#include <QActionGroup>
#include <QTreeWidgetItem>
#include <QTableWidgetItem>
#include <memory>

struct PacketListData {
    QTableWidgetItem* timeElapsed;
    QTableWidgetItem* source;
    QTableWidgetItem* destination;
    QTableWidgetItem* protocol;
    QTableWidgetItem* length;
    QTableWidgetItem* info;

    PacketListData(QTableWidgetItem* time, QTableWidgetItem* src, QTableWidgetItem* dst, QTableWidgetItem* proto, QTableWidgetItem* len, QTableWidgetItem* inf)
    : timeElapsed(time), source(src), destination(dst), protocol(proto), length(len), info(inf) {}
};

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget* parent = nullptr);
    ~MainWindow();

    std::shared_ptr<Sniffer> sniffer;
    std::shared_ptr<PacketParser> parser;

private:
    Ui::MainWindow* ui;

    // menu
    QMenu* fileMenu;
    QMenu* deviceMenu;
    QMenu* analysisMenu;
    QMenu* statisticsMenu;
    QMenu* helpMenu;

    // toolBar
    QAction* startCaptureAction;
    QAction* stopCaptureAction;
    QAction* openPacketAction;
    QAction* savePacketAction;
    QAction* enableScrollingAction;
    QAction* exitAction;

    // deviceBar
    QAction* searchDeviceAction;
    QAction* closeDeviceAction;
    QList<QAction*> deviceActions;
    std::shared_ptr<QActionGroup> actionGroup;

    CaptureThread* captureThread;
    std::function<void(u_char* user, const struct pcap_pkthdr* header, const u_char* packet)> packetHandler;

    std::vector<PacketListData*> packetLists;
    std::vector<QTreeWidgetItem*> ethernetItems;
    std::vector<QString> hexViews;
    unsigned int packetListIndex;

    std::vector<const pcap_pkthdr*> headers;
    std::vector<const u_char*> packets;
    std::vector<int> filteredIndex;

    const pcap_pkthdr* currentHeader;
    const u_char* currentPacket;

    bool autoScrollEnabled;

    void setupPacketList();
    void setupAction();
    void setupMenu();
    void setupToolBar();
    void setupDeviceBar();
    void setupConnection();

    void connectDeviceAction(pcap_if_t* dev);

    void updatePacketLists(ParsedPacket* parsedPacket, const struct pcap_pkthdr* header);
    void updatePacketDetails(ParsedPacket* parsedPacket, const struct pcap_pkthdr* header);
    void updateHexViews(ParsedPacket* parsedPacket, const struct pcap_pkthdr* header, const u_char* packet);
    void pushPacketList(int idx);

    void clearLastCapture();
};
#endif // MAINWINDOW_H
