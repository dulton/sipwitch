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
#include "ui_mapped.h"
#include <QTime>

using namespace UCOMMON_NAMESPACE;
using namespace SIPWITCH_NAMESPACE;

static QMenu *menu;
static Ui::Mapped ui;
static QAction *optionsAction;
static QAction *reconnectAction;
static QAction *reloadAction;
static int active = 0;

Mapped *mapped = NULL;

static void add(QTableWidget *table, const QTime& when, int row, int col)
{
    QTableWidgetItem *item = new QTableWidgetItem;

    item->setData(Qt::DisplayRole, when);
    table->setItem(row, col, item);
}

static void add(QTableWidget *table, const char *text, int row, int col)
{
    QTableWidgetItem *item = new QTableWidgetItem;

    item->setText(text);
    table->setItem(row, col, item);
}

static void paddress(char *buffer, size_t size, struct sockaddr_internet *a1, struct sockaddr_internet *a2)
{
    assert(a1 != NULL);

    char sep = '\n';
    char buf[64];
    unsigned p1 = 0, p2 = 0;

    if(!a1)
        return;

    Socket::query((struct sockaddr *)a1, buf, sizeof(buf));
    switch(a1->address.sa_family) {
    case AF_INET:
        p1 = (unsigned)ntohs(a1->ipv4.sin_port);
        break;
#ifdef  AF_INET6
    case AF_INET6:
        p1 = (unsigned)ntohs(a1->ipv6.sin6_port);
        break;
#endif
    }

    if(a2) {
        switch(a2->address.sa_family) {
        case AF_INET:
            p2 = (unsigned)ntohs(a2->ipv4.sin_port);
            break;
#ifdef  AF_INET6
        case AF_INET6:
            p2 = (unsigned)ntohs(a2->ipv6.sin6_port);
            break;
#endif
        }
    }

    if(a2 && p2)
        sep = ',';

    if(p1)
        snprintf(buffer, size, "%s:%u%c", buf, p1, sep);
    else
        snprintf(buffer, size, "none%c", sep);

    if(!a2 || !p2)
        return;

    Socket::query((struct sockaddr *)a2, buf, sizeof(buf));
    snprintf(buffer, size, "%s:%u\n", buf, p2);
}

static void remapStats(void)
{
    QTableWidget *table = ui.statsTable;
    unsigned count = 0;
    unsigned index = 0;
    stats map;
    time_t now;
    int row;
    char limit[8], id[16], total[32], current[32], peak[32];
    char period[32], min[32], max[32];

    table->setUpdatesEnabled(false);
    table->clearContents();

    row = table->rowCount();
    while(row-- > 0)
        table->removeRow(row);

    if(mapped_calls)
        count = mapped_calls->count();

    time(&now);
    row = 0;

    while(index < count) {
        statmap_t   &sta = *mapped_stats;
        sta.copy(index++, &map);

        if(!map.id[0])
            break;

        snprintf(id, sizeof(id), "%-12s", map.id);
        if(map.limit)
            snprintf(limit, sizeof(limit), "%05hu", map.limit);
        else
            snprintf(limit, sizeof(limit), "-    ");

        snprintf(total, sizeof(total), "%lu/%lu",
            map.data[0].total, map.data[1].total);

        snprintf(current, sizeof(current), "%hu/%hu",
            map.data[0].current, map.data[1].current);

        snprintf(peak, sizeof(peak), "%hu/%hu",
            map.data[0].peak, map.data[1].peak);

        snprintf(period, sizeof(period), "%lu/%lu",
            map.data[0].pperiod, map.data[1].pperiod);

        snprintf(min, sizeof(min), "%hu/%hu",
            map.data[0].pmin, map.data[1].pmin);

        snprintf(max, sizeof(max), "%hu/%hu",
            map.data[0].pmax, map.data[1].pmax);

        table->insertRow(row);
        add(table, id, row, 0);
        add(table, limit, row, 1);
        add(table, total, row, 2);
        add(table, current, row, 3);
        add(table, peak, row, 4);
        add(table, period, row, 5);
        add(table, min, row, 6);
        add(table, max, row, 7);
        ++row;
    }

    table->setUpdatesEnabled(true);
    table->update();
}

static void remapCalls(void)
{
    QTableWidget *table = ui.callTable;
    unsigned count = 0;
    unsigned index = 0;
    MappedCall map;
    time_t now;
    int row;

    table->setUpdatesEnabled(false);
    table->clearContents();

    row = table->rowCount();
    while(row-- > 0)
        table->removeRow(row);

    if(mapped_calls)
        count = mapped_calls->count();

    time(&now);
    row = 0;

    while(index < count) {
        callmap_t   &calls = *mapped_calls;
        calls.copy(index++, &map);

        if(!map.created || !map.source[0])
            continue;

        const char *call_state = map.state + 1;
        const char *call_display = map.display;
        const char *call_from = map.source;
        const char *call_dialed = "none";

        if(map.active)
            call_dialed = map.target;

        table->insertRow(row);
        add(table, call_state, row, 1);
        add(table, call_from, row, 2);
        add(table, call_dialed, row, 3);
        add(table, call_display, row, 4);
        ++row;
    }

    table->setUpdatesEnabled(true);
    table->update();
}

static void remapUsers(void)
{
    QTableWidget *table = ui.usersTable;
    unsigned count = 0;
    unsigned row = 0, index = 0;
    MappedRegistry buffer;
    time_t now;
    char ext[8], use[8], addr[128];
    const char *type;
    bool expflag;
    QTime expires;
    struct tm *dt;

    table->setUpdatesEnabled(false);
    table->clearContents();

    row = table->rowCount();
    while(row-- > 0)
        table->removeRow(row);

    if(mapped_users)
        count = mapped_users->count();

    time(&now);
    row = 0;
    while(index < count) {
        usermap_t   &reg = *mapped_users;
        reg.copy(index++, &buffer);

        if(buffer.type == MappedRegistry::EXPIRED)
            continue;
        else if(buffer.type == MappedRegistry::TEMPORARY && !buffer.inuse)
            continue;

        ext[0] = 0;
        if(buffer.ext)
            snprintf(ext, sizeof(ext), "%7d", buffer.ext);
        expflag = false;
        snprintf(use, sizeof(use), "%u", buffer.inuse);
        if(buffer.expires && buffer.type != MappedRegistry::TEMPORARY) {
            dt = localtime((const time_t *)(&buffer.expires));
            expflag = true;
            expires.setHMS(dt->tm_hour, dt->tm_min, dt->tm_sec);
        }
        switch(buffer.type) {
        case MappedRegistry::REJECT:
            type = "rej";
            break;
        case MappedRegistry::REFER:
            type = "ref";
            break;
        case MappedRegistry::GATEWAY:
            type = "gw";
            break;
        case MappedRegistry::SERVICE:
            type = "svc";
            break;
        case MappedRegistry::TEMPORARY:
            type = "temp";
            break;
        default:
            type = "user";
        };
//      printf("%7s %-30s %-4s %-30s %4s %7s ", ext, buffer.userid, type, buffer.profile.id, use, exp);
        paddress(addr, sizeof(addr), &buffer.contact, NULL);

        table->insertRow(row);
        add(table, ext, row, 0);
        add(table, buffer.userid, row, 1);
        add(table, type, row, 2);
        add(table, buffer.profile.id, row, 3);
        add(table, use, row, 4);
        if(expflag)
            add(table, expires, row, 5);
        else
            add(table, "-", row, 6);
        add(table, addr, row, 6);
        ++row;
    }

    table->setUpdatesEnabled(true);
    table->update();
}

Mapped::Mapped() :
QDialog(switchview)
{
#ifdef  _MSWINDOWS_
    char buf[128];
    DWORD size = sizeof(buf);
    if(GetUserNameA(buf, &size))
        userid = buf;
    else
        userid = "unknown";
#else
    userid = getlogin();
#endif

    ui.setupUi((QDialog *)this);

    QSettings settings;
    restoreGeometry(settings.value("ui/mapped").toByteArray());

    menu = new QMenu();

    QAction *aboutAction = new QAction(tr("About"), this);
    connect(aboutAction, SIGNAL(triggered()),
        switchview, SLOT(about()));
    menu->addAction(aboutAction);

    optionsAction = new QAction(tr("&Options"), this);
    connect(optionsAction, SIGNAL(triggered()),
        switchview, SLOT(openOptions()));
    menu->addAction(optionsAction);

    reconnectAction = new QAction(tr("Reconnect"), this);
    connect(reconnectAction, SIGNAL(triggered()),
        switchview, SLOT(reconnect()));

    menu->addAction(reconnectAction);

    reloadAction = new QAction(tr("Reload"), this);
    menu->addAction(reloadAction);

    setContextMenuPolicy(Qt::CustomContextMenu);
    connect(this, SIGNAL(customContextMenuRequested(const QPoint&)),
        this, SLOT(mappedMenu(const QPoint&)));

    connect(ui.closeButton, SIGNAL(clicked()),
        this, SLOT(close()));

    connect(ui.clearButton, SIGNAL(clicked()),
        this, SLOT(clearList()));

    connect(ui.reloadButton, SIGNAL(clicked()),
        dispatcher, SLOT(reload()));

    connect(ui.realmEditor, SIGNAL(returnPressed()),
        dispatcher, SLOT(changeRealm()));

    connect(ui.stateEditor, SIGNAL(returnPressed()),
        dispatcher, SLOT(changeState()));

    connect(this, SIGNAL(closed()),
        switchview, SLOT(mappedClosed()));

    connect(this, SIGNAL(clearActivity()),
        ui.activityList, SLOT(clear()));

    connect(this, SIGNAL(clearHistory()),
        ui.historyTable, SLOT(clear()));

    connect(ui.tabs, SIGNAL(currentChanged(int)),
        this, SLOT(selectedTab(int)));

    connect(dispatcher, SIGNAL(activateSignal(events*)),
        this, SLOT(activateUser(events*)), Qt::QueuedConnection);

    connect(dispatcher, SIGNAL(releaseSignal(events*)),
        this, SLOT(releaseUser(events*)), Qt::QueuedConnection);

    connect(dispatcher, SIGNAL(callSignal(events*)),
        this, SLOT(callUpdate(events*)), Qt::QueuedConnection);

    connect(dispatcher, SIGNAL(dropSignal(events*)),
        this, SLOT(dropUpdate(events*)), Qt::QueuedConnection);

    connect(dispatcher, SIGNAL(notifySignal(events*)),
        this, SLOT(notifyActivity(events*)), Qt::QueuedConnection);

    connect(dispatcher, SIGNAL(realmSignal(char*)),
        this, SLOT(changeRealm(char*)), Qt::QueuedConnection);

    connect(dispatcher, SIGNAL(contactSignal(char*)),
        this, SLOT(changeContact(char*)), Qt::QueuedConnection);

    connect(dispatcher, SIGNAL(publishSignal(char*)),
        this, SLOT(changePublish(char*)), Qt::QueuedConnection);

    connect(dispatcher, SIGNAL(stateSignal(char*,char *)),
        this, SLOT(changeState(char*,char*)), Qt::QueuedConnection);
}

void Mapped::mappedMenu(const QPoint& pos)
{
    menu->exec(mapToGlobal(pos));
}

void Mapped::started(const char *text)
{
    ui.started->setText(text);
    ui.started->update();
}

void Mapped::changeContact(char *text)
{
    ui.labelServer->setText(text);
    char *cp = strchr(text, ':');
    if(*cp) {
        *(cp++) = 0;
    }
    else
        cp = text;
    string_t tmp = str((const char *)text) + ":" + userid + "@" + (const char *)cp;
    ui.labelIdentity->setText(*tmp);
    free(text);
}

void Mapped::changePublish(char *text)
{
    char *cp = strchr(text, ':');
    if(*cp) {
        *(cp++) = 0;
    }
    else
        cp = text;
    string_t tmp = str((const char *)text) + ":" + userid + "@" + (const char *)cp;
    ui.labelPublished->setText(*tmp);
    free(text);
}

void Mapped::changeRealm(char *text)
{
    ui.realmEditor->setText(text);
    ui.realmEditor->update();
    ui.labelRealm->setText(text);
    free(text);
}

void Mapped::changeState(char *text, char *start)
{
    if(start) {
        started(start);
        free(start);
    }

    ui.stateEditor->setText(text);
    ui.stateEditor->update();
    free(text);
}

void Mapped::notifyActivity(events *msg)
{
    switch(msg->type)
    {
    case events::WARNING:
        new QListWidgetItem(QIcon::fromTheme("dialog-warning"), msg->reason, ui.activityList);
        if(options->notify[NOTIFY_WARNING] && trayicon)
            trayicon->showMessage("SwitchView", msg->reason, QSystemTrayIcon::Warning);
        break;
    case events::NOTICE:
        new QListWidgetItem(QIcon::fromTheme("dialog-information"), msg->reason, ui.activityList);
        if(options->notify[NOTIFY_INFO] && trayicon)
            trayicon->showMessage("SwitchView", msg->reason, QSystemTrayIcon::Information);
        break;
    case events::FAILURE:
    case events::TERMINATE:
        new QListWidgetItem(QIcon::fromTheme("dialog-error"), msg->reason, ui.activityList);
        if(options->notify[NOTIFY_ERRORS] && trayicon && msg->type == events::FAILURE)
            trayicon->showMessage("SwitchView", msg->reason, QSystemTrayIcon::Critical);
        break;
    default:
        break;
    }
    ui.activityList->update();
    delete msg;
}

const char *Mapped::realm(void)
{
    return ui.realmEditor->text().toAscii().data();
}

const char *Mapped::state(void)
{
    return ui.stateEditor->text().toAscii().data();
}

void Mapped::closeEvent(QCloseEvent *event)
{
    if(isVisible()) {
        QSettings settings;
        settings.setValue("ui/mapped", saveGeometry());
    }

    emit closed();
    QDialog::closeEvent(event);
}

void Mapped::start(void)
{
    mapped = new Mapped();
}

void Mapped::stop(void)
{
    if(mapped) {
        mapped->close();
        delete mapped;
        mapped = NULL;
    }
}

void Mapped::clearList(void)
{
    switch(active) {
    case ACTIVITY:
        emit clearActivity();
        break;
    case HISTORY:
        emit clearHistory();
        break;
    default:
        break;
    }
}

void Mapped::selectedTab(int index)
{
    active = index;

    switch(active) {
    case USERS:
        ui.clearButton->setEnabled(false);
        remapUsers();
        break;
    case CALLS:
        ui.clearButton->setEnabled(false);
        remapCalls();
        break;
    case ACTIVITY:
    case HISTORY:
        ui.clearButton->setEnabled(true);
        break;
    case STATS:
        ui.clearButton->setEnabled(false);
        remapStats();
    }
}

void Mapped::callUpdate(events *msg)
{
    char title[128];
    char text[128];

    if(trayicon && options->notify[NOTIFY_CALLS]->isChecked()) {
        snprintf(title, sizeof(title), "calling %s", msg->call.dialed);
        if(msg->call.display[0])
            snprintf(text, sizeof(text), "Incoming call from %s",
                msg->call.display);
        else
            snprintf(text, sizeof(text), "Incoming call from %s",
                msg->call.caller);

        trayicon->showMessage(title, text, QSystemTrayIcon::Information);
    }

    // if active tab push update...
    if(active == CALLS)
        remapCalls();
    else if(active == STATS)
        remapStats();

    delete msg;
}

void Mapped::dropUpdate(events *msg)
{
    QTime started;
    QTableWidget *table = ui.historyTable;
    int row = table->rowCount();
    struct tm *dt = localtime((const time_t *)(&msg->call.started));
    time_t now;
    char duration[16];

    started.setHMS(dt->tm_hour, dt->tm_min, dt->tm_sec);
    time(&now);
    snprintf(duration, sizeof(duration), "%ld", (long)(now - msg->call.started));

    // if active tab push update...
    if(active == CALLS)
        remapCalls();
    else if(active == STATS)
        remapStats();

    table->insertRow(row);
    add(table, msg->call.network, row, 0);
    add(table, started, row, 1);
    add(table, duration, row, 2);
    add(table, msg->call.caller, row, 3);
    add(table, msg->call.dialed, row, 4);
    add(table, msg->call.reason, row, 5);
    delete msg;
}

void Mapped::releaseUser(events *msg)
{
    char buf[128];

    // if active tab push update...
    if(active == USERS)
        remapUsers();
    else if(active == STATS)
        remapStats();

    if(trayicon && options->notify[NOTIFY_REGISTRY]->isChecked()) {
        if(msg->user.extension)
            snprintf(buf, sizeof(buf), "releasing %s at ext %d",
                msg->user.id, msg->user.extension);
        else
            snprintf(buf, sizeof(buf), "releasing %s", msg->user.id);

        trayicon->showMessage("SwitchView", buf, QSystemTrayIcon::Information);
    }

    delete msg;
}

void Mapped::activateUser(events *msg)
{
    char buf[128];

    if(trayicon && options->notify[NOTIFY_REGISTRY]->isChecked()) {
        if(msg->user.extension)
            snprintf(buf, sizeof(buf), "activating %s on ext %d",
                msg->user.id, msg->user.extension);
        else
            snprintf(buf, sizeof(buf), "activating %s", msg->user.id);

        trayicon->showMessage("SwitchView", buf, QSystemTrayIcon::Information);

    }

    // if active tab push update...
    if(active == USERS)
        remapUsers();
    else if(active == STATS)
        remapStats();

    delete msg;
}

void Mapped::open(void)
{
    if(Events::isAdmin()) {
        ui.realmEditor->setReadOnly(false);
        ui.stateEditor->setReadOnly(false);
        ui.reloadButton->setEnabled(true);
    }
    else {
        ui.realmEditor->setReadOnly(true);
        ui.stateEditor->setReadOnly(true);
        ui.reloadButton->setEnabled(false);
    }
    active = ui.tabs->currentIndex();
    selectedTab(active);
    QDialog::open();
    show();
}
