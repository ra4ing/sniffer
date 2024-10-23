#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "sniffer.h"
#include "parser.h"
#include <QMainWindow>

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
    QList<QAction*> deviceActions;

private:
    Ui::MainWindow* ui;
    Sniffer sniffer;
    PacketParser parser;

    void setupAction();
    void setupConnection();
    void setupMenu();
    void setupToolBar();
    void setupDeviceBar();
    void connectDeviceAction(pcap_if_t* dev);
    void packetHandler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet);
};
#endif // MAINWINDOW_H
