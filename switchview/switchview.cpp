// Copyright (C) 2011 David Sugar, Haakon Eriksen, GNU Free Call Foundation
//
// This file is part of SwitchView.
//
// SwitchView is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// SwitchView is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with SwitchView.  If not, see <http://www.gnu.org/licenses/>.

#include "switchview.h"
#include <QTimer>

SwitchView *switchview = NULL;
QSystemTrayIcon *trayicon = NULL;

bool testing = false;
bool startup = false;
bool alwaysopen = false;

static QAction *optionsAction;
static QAction *mappedAction;
static QAction *reconnectAction;
static QAction *reloadAction;
static bool connected = false;
static bool stopping = false;
static bool initial = true;

static void warning(void)
{
    if(mapped->isVisible())
        return;

    QString text = SwitchView::tr("No server connected");
    QMessageBox::warning(switchview, SwitchView::tr("SwitchView"), text);
}

SwitchView::SwitchView() :
QMainWindow(NULL)
{
    // singleton...
    Q_ASSERT(switchview == NULL);
    switchview = this;

    QAction *aboutAction = new QAction(tr("About"), this);
    aboutAction->setIcon(QIcon::fromTheme("help-about"));
    aboutAction->setIconVisibleInMenu(true);
    connect(aboutAction, SIGNAL(triggered()), this, SLOT(about()));

    optionsAction = new QAction(tr("&Options"), this);
    optionsAction->setIcon(QIcon::fromTheme("preferences-other"));
    optionsAction->setIconVisibleInMenu(true);
    connect(optionsAction, SIGNAL(triggered()), this, SLOT(openOptions()));

    reconnectAction = new QAction(tr("Reconnect"), this);
    reconnectAction->setIcon(QIcon::fromTheme("connect_creating"));
    reconnectAction->setIconVisibleInMenu(true);
    connect(reconnectAction, SIGNAL(triggered()), this, SLOT(reconnect()));

    reloadAction = new QAction(tr("Reload"), this);
    reloadAction->setIcon(QIcon::fromTheme("reload"));
    reloadAction->setIconVisibleInMenu(true);

    mappedAction = new QAction(tr("&Status"), this);
    mappedAction->setIcon(QIcon::fromTheme("dialog-information"));
    mappedAction->setIconVisibleInMenu(true);
    connect(mappedAction, SIGNAL(triggered()), this, SLOT(openMapped()));

    QAction *quitAction = new QAction(tr("&Quit"), this);
    quitAction->setIcon(QIcon::fromTheme("exit"));
    quitAction->setIconVisibleInMenu(true);
    connect(quitAction, SIGNAL(triggered()), qApp, SLOT(quit()));

    QApplication::setQuitOnLastWindowClosed(false);

    setWindowIcon(QIcon(":/live.png"));
    setWindowFlags(Qt::Window);

    QMenu *traymenu = new QMenu(NULL);
    traymenu->addAction(aboutAction);
    traymenu->addAction(optionsAction);
    traymenu->addSeparator();
    traymenu->addAction(reconnectAction);
    traymenu->addAction(reloadAction);
    traymenu->addAction(mappedAction);
    traymenu->addSeparator();
    traymenu->addAction(quitAction);

    Options::start();

    trayicon = new QSystemTrayIcon(this);
    if(Options::isTray()) {
        trayicon->setContextMenu(traymenu);
        trayicon->setIcon(QIcon(":/down.png"));
        trayicon->show();
    }

    connect(qApp, SIGNAL(aboutToQuit()),
        this, SLOT(stop()));

    if(Options::isTray())
        connect(trayicon, SIGNAL(activated(QSystemTrayIcon::ActivationReason)),
            this, SLOT(action(QSystemTrayIcon::ActivationReason)));

    Events::start();
    Mapped::start();

    if(!Options::isTray())
        QApplication::setQuitOnLastWindowClosed(true);

    if(alwaysopen)
        openMapped();
}

SwitchView::~SwitchView()
{
    options->setParent(NULL);   // kill connection to mapped before close...
    mapped->setParent(NULL);

    stopping = true;

    Mapped::stop();
    Events::stop();
    Options::stop();
}

void SwitchView::stop(void)
{
    delete this;
    switchview = NULL;
}

void SwitchView::online(void)
{
    if(connected)
        return;

    if(!initial && options->notify[NOTIFY_CONNECTING] && trayicon)
        trayicon->showMessage("SwitchView", "Reconnected to the server");

    initial = false;

    if(Options::isTray())
        trayicon->setIcon(QIcon(":/live.png"));
#if defined(AF_UNIX) && !defined(_MSWINDOWS_)
    reconnectAction->setVisible(false);
#endif
    mappedAction->setVisible(true);
    connected = true;
}

void SwitchView::reconnect(void)
{
#if defined(AF_UNIX) && !defined(_MSWINDOWS_)
    if(connected)
        return;

#else
    if(connected) {
        mapped->close();
        mappedAction->setEnabled(false);
        if(Options::isTray())
            trayicon->setIcon(QIcon(":/down.png"));
        connected = false;
    }
#endif
    Events::reconnect();
}

void SwitchView::offline(void)
{
    if(initial) {
        if(!startup)
            warning();
        initial = false;
        return;
    }

    if(!connected)
        return;

    mapped->close();

    if(trayicon && trayicon->supportsMessages() && options->notify[NOTIFY_DISCONNECT])
        trayicon->showMessage("SwitchView", "Server connection lost", QSystemTrayIcon::Critical);
    else if(!alwaysopen)
        QMessageBox::critical(NULL, tr("SwitchView"),
            tr("Server connection lost\n\n"));

    if(Options::isTray())
        trayicon->setIcon(QIcon(":/down.png"));
    reconnectAction->setVisible(true);
    connected = false;
}

void SwitchView::openOptions(void)
{
    optionsAction->setEnabled(false);
    mapped->setEnabled(false);
    mappedAction->setEnabled(false);    // kill menu entry...
    options->open();
    options->setEnabled(true);
    options->show();
}

void SwitchView::openMapped(void)
{
    if(!connected && !testing && !alwaysopen)
        warning();
    else if(!mapped->isVisible() && mapped->isEnabled()) {
        mappedAction->setEnabled(false);
        mapped->open();
    }
}

void SwitchView::mappedClosed(void)
{
    if(stopping)
        return;

    mappedAction->setEnabled(true);
}

void SwitchView::optionsClosed(void)
{
    if(stopping)
        return;

    optionsAction->setEnabled(true);
    mapped->setEnabled(true);
    if(!mapped->isVisible() && connected)
        mappedAction->setEnabled(true);
}

void SwitchView::about(void)
{
    QString text = tr("Version") + " " VERSION "\n\n";
    QWidget *parent = this;
    if(mapped->isVisible())
        parent = mapped;
    mapped->setEnabled(false);
    QMessageBox::about(parent, tr("About SwitchView"), text);
    mapped->setEnabled(true);
}

void SwitchView::action(QSystemTrayIcon::ActivationReason reason)
{
    switch(reason) {
    case QSystemTrayIcon::Trigger:
    case QSystemTrayIcon::DoubleClick:
        if(!connected && !testing) {
            warning();
            return;
        }
        mappedAction->setEnabled(false);
        if(mapped->isVisible())
            mapped->close();
        else if(mapped->isEnabled())
            mapped->open();
        return;
    default:
        return;
    }
}
