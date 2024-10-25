#include "mainwindow.h"
#include "sniffer.h"

#include <thread>
#include <QApplication>
#include <QFont>
#include <QFontDatabase>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    QFont font("Microsoft YaHei", 10);
    a.setFont(font);

    MainWindow w;
    w.show();
    return a.exec();
}
