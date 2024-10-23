#include "mainwindow.h"
#include "sniffer.h"

#include <thread>
#include <QApplication>
#include <QLocale>                      
#include <QTranslator>

int main(int argc, char *argv[])
{
    // std::thread 

    QApplication a(argc, argv);

    // QTranslator translator;
    // const QStringList uiLanguages = QLocale::system().uiLanguages();
    // for (const QString &locale : uiLanguages) {
    //     const QString baseName = "sniffer_" + QLocale(locale).name();
    //     if (translator.load(":/i18n/" + baseName)) {
    //         a.installTranslator(&translator);
    //         break;
    //     }
    // }
    MainWindow w;
    w.show();
    return a.exec();

    // Sniffer sniffer;
    // sniffer.getDevs();
}
