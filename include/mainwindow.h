#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "sniffer.h"
#include "parser.h"
#include <QMainWindow>
#include <QActionGroup>
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

    std::shared_ptr<Sniffer> sniffer;
    std::shared_ptr<PacketParser> parser;

    void setupPacketList();
    void setupAction();
    void setupMenu();
    void setupToolBar();
    void setupDeviceBar();

    void setupConnection();

    void connectDeviceAction(pcap_if_t* dev);
};
#endif // MAINWINDOW_H
