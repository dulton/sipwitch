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

#ifndef SWITCHVIEW_H_
#define SWITCHVIEW_H_

#include <config.h>
#include <ucommon/ucommon.h>
#include <sipwitch/sipwitch.h>
#include <QWidget>
#include <QTabWidget>
#include <QSystemTrayIcon>
#include <QObject>
#include <QMenu>
#include <QApplication>
#include <QMessageBox>
#include <QCheckBox>
#include <QLayout>
#include <QCloseEvent>
#include <QPushButton>
#include <QLabel>
#include <QListWidget>
#include <QMainWindow>
#include <QSettings>
#include <QIcon>

using namespace UCOMMON_NAMESPACE;
using namespace SIPWITCH_NAMESPACE;

typedef mapped_view<stats>  statmap_t;
typedef mapped_view<MappedRegistry> usermap_t;
typedef mapped_view<MappedCall> callmap_t;

enum {
    NOTIFY_CONNECTING = 0, NOTIFY_DISCONNECT,
    NOTIFY_ERRORS, NOTIFY_WARNING, NOTIFY_INFO,
    NOTIFY_REGISTRY, NOTIFY_CALLS, NOTIFY_COUNT};

class __LOCAL SwitchView : public QMainWindow
{
    Q_OBJECT

private:
    SwitchView();
    ~SwitchView();

public:
    inline static void start(void)
        {new SwitchView();};

public slots:
    void stop(void);

    void online(void);
    void offline(void);
    void reconnect(void);

    void about(void);
    void action(QSystemTrayIcon::ActivationReason reason);

    void openMapped(void);
    void openOptions(void);

    void mappedClosed(void);        // user dialog view closed.
    void optionsClosed(void);   // options closed
};

// sipwitch event manager, will signal other things when sipwitch
// events occur.

class __LOCAL Events : public QObject, public JoinableThread
{
    Q_OBJECT

public:
    Events();
    ~Events();

    void run(void);

    bool dispatch(events *msg);

    static bool reconnect(void);

    static void start(void);

    static void stop(void);

    static bool isAdmin(void);

    static bool realm(const char *new_realm);

    static bool state(const char *new_state);

public slots:
    void reload(void);
    void changeRealm(void);
    void changeState(void);

signals:
    void serverOnlineSignal(void);
    void serverOfflineSignal(void);
    void activateSignal(events*);
    void releaseSignal(events*);
    void callSignal(events*);
    void dropSignal(events*);
    void notifySignal(events*);
    void stateSignal(char *changed, char *started = NULL);
    void realmSignal(char *changed);
};

class __LOCAL Mapped : public QDialog
{
    Q_OBJECT

private:
    void closeEvent(QCloseEvent *event);

    void started(const char *text);

public:
    enum {ACTIVITY = 0, CALLS, HISTORY, STATS, USERS};

    Mapped();

    static void start(void);
    static void stop(void);

    void open(void);

    const char *realm(void);

    const char *state(void);

signals:
    void closed(void);

    void clearActivity();

    void clearHistory();

public slots:
    void mappedMenu(const QPoint&);

    void selectedTab(int index);

    void clearList(void);

    void activateUser(events *msg);
    void releaseUser(events *msg);
    void callUpdate(events *msg);
    void dropUpdate(events *msg);
    void notifyActivity(events *msg);
    void realm(char *text);
    void state(char *text, char *start);
};

class __LOCAL Options : public QDialog
{
    Q_OBJECT

private:
    void closeEvent(QCloseEvent *event);
    void reload(void);

public:
    Options();

    QCheckBox *notify[NOTIFY_COUNT];

    static void start(void);
    static void stop(void);
    static bool isTray(void);

public slots:
    void accept(void);
    void cancel(void);

signals:
    void closed(void);
};

// why make singleton access complex?
extern SwitchView *switchview;
extern Events *dispatcher;
extern Mapped *mapped;
extern Options *options;
extern QSystemTrayIcon *trayicon;

extern bool alwaysopen;
extern bool testing;
extern bool startup;

extern callmap_t *mapped_calls;
extern usermap_t *mapped_users;
extern statmap_t *mapped_stats;

#endif

