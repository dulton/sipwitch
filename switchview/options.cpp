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
#include "ui_options.h"

using namespace UCOMMON_NAMESPACE;
using namespace SIPWITCH_NAMESPACE;

static Ui::Options ui;
Options *options = NULL;

Options::Options() :
QDialog(mapped)
{
    ui.setupUi((QDialog *)this);

    connect(ui.buttonBox, SIGNAL(accepted()),
        this, SLOT(accept()));

    connect(ui.buttonBox, SIGNAL(rejected()),
        this, SLOT(cancel()));

    connect(this, SIGNAL(closed()),
        switchview, SLOT(optionsClosed()));

    notify[NOTIFY_CONNECTING] = ui.notifyConnecting;
    notify[NOTIFY_DISCONNECT] = ui.notifyDisconnect;
    notify[NOTIFY_ERRORS] = ui.notifyErrors;
    notify[NOTIFY_WARNING] = ui.notifyWarning;
    notify[NOTIFY_INFO] = ui.notifyInfo;
    notify[NOTIFY_REGISTRY] = ui.notifyRegistry;
    notify[NOTIFY_CALLS] = ui.notifyCalls;

    QSettings settings;
    restoreGeometry(settings.value("ui/options").toByteArray());
    reload();
}

void Options::reload(void)
{
    QSettings settings;
    notify[NOTIFY_CONNECTING]->setChecked(
        settings.value("notify/connecting", false).toBool());
    notify[NOTIFY_DISCONNECT]->setChecked(
        settings.value("notify/disconnect", false).toBool());
    notify[NOTIFY_ERRORS]->setChecked(
        settings.value("notify/errors", false).toBool());
    notify[NOTIFY_WARNING]->setChecked(
        settings.value("notify/warning", false).toBool());
    notify[NOTIFY_INFO]->setChecked(
        settings.value("notify/info", false).toBool());
    notify[NOTIFY_REGISTRY]->setChecked(
        settings.value("notify/registry", false).toBool());
    notify[NOTIFY_CALLS]->setChecked(
        settings.value("notify/calls", false).toBool());

    ui.desktopTray->setChecked(
        settings.value("desktop/tray", true).toBool());

    ui.desktopMenu->setChecked(
        settings.value("desktop/menu", true).toBool());
}

void Options::closeEvent(QCloseEvent *event)
{
    if(isVisible()) {
        QSettings settings;
        settings.setValue("ui/options", saveGeometry());
    }

    emit closed();
    QDialog::closeEvent(event);
}

void Options::accept(void)
{
    QSettings settings;

    settings.setValue("notify/connecting",
        notify[NOTIFY_CONNECTING]->isChecked());

    settings.setValue("notify/disconnect",
        notify[NOTIFY_DISCONNECT]->isChecked());

    settings.setValue("notify/errors",
        notify[NOTIFY_ERRORS]->isChecked());

    settings.setValue("notify/warning",
        notify[NOTIFY_WARNING]->isChecked());

    settings.setValue("notify/info",
        notify[NOTIFY_INFO]->isChecked());

    settings.setValue("notify/registry",
        notify[NOTIFY_REGISTRY]->isChecked());

    settings.setValue("notify/calls",
        notify[NOTIFY_CALLS]->isChecked());

    settings.setValue("desktop/tray",
        ui.desktopTray->isChecked());

    settings.setValue("desktop/menu",
        ui.desktopMenu->isChecked());

    settings.sync();

    close();
}

bool Options::isTray(void)
{
    if(!trayicon || alwaysopen)
        return false;

    return ui.desktopTray->isChecked();
}

void Options::cancel(void)
{
    reload();   // reset to last saved state...
    close();
}

void Options::start(void)
{
    options = new Options();
}

void Options::stop(void)
{
    if(options) {
        options->close();
        delete options;
        options = NULL;
    }
}
