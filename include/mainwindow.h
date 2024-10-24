#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "sniffer.h"
#include "parser.h"
#include "captureThread.h"
#include <QMainWindow>
#include <QActionGroup>
#include <QTreeWidgetItem>
#include <memory>

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
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

    std::vector<QTreeWidgetItem*> ethernetItems;
    std::vector<QString> hexViews;
    std::vector<const pcap_pkthdr*> headers;
    std::vector<const u_char*> packets;
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

    void updatePacketList(ParsedPacket* parsedPacket, const struct pcap_pkthdr* header);
    void updatePacketDetail(ParsedPacket* parsedPacket, const struct pcap_pkthdr* header);
    void updateHexView(ParsedPacket* parsedPacket, const struct pcap_pkthdr* header, const u_char* packet);

    void clearLastCapture();
};
#endif // MAINWINDOW_H
