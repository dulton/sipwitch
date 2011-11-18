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
#include <QTranslator>
#include <QLocale>

// this assures qt translations are up before initializing argument parser...

static void parse(int argc, char **argv)
{
    shell::flagopt helpflag('h',"--help", strdup(SwitchView::tr("display this list").toAscii().data()));
    shell::flagopt althelp('?', NULL, NULL);
    shell::flagopt admin('a', "--admin", strdup(SwitchView::tr("when starting as admin application").toAscii().data()));
    shell::flagopt start('s', "--startup", strdup(SwitchView::tr("when starting at user login").toAscii().data()));
    shell::flagopt test('t', "--testing", strdup(SwitchView::tr("testing without warnings").toAscii().data()));

    shell args(argc, argv);

    if(is(helpflag) || is(althelp)) {
        printf("%s\n", SwitchView::tr("Usage: switchview [options]...").toAscii().data());
        printf("%s\n\n", SwitchView::tr("GNU SIP Witch Desktop Control").toAscii().data());
        printf("%s\n", SwitchView::tr("Options:").toAscii().data());
        shell::help();
        printf("\n%s\n", SwitchView::tr("Report bugs to dyfet@gnu.org").toAscii().data());
        exit(0);
    }

    if(is(test)) {
        startup = true;
        testing = true;
    }

    if(is(admin))
        alwaysopen = true;

    if(is(start))
        startup = true;
}

PROGRAM_MAIN(argc, argv)
{
    shell::bind("switchview");
    shell::relocate(*argv);

    QApplication app(argc, argv);

    QCoreApplication::setOrganizationName("GNU Telephony");
    QCoreApplication::setOrganizationDomain("gnutelephony.org");
    QCoreApplication::setApplicationName("SwitchView");

    QTranslator translator;
    translator.load(QLocale::system().name(), *shell::path(shell::SYSTEM_PREFIX, TRANSLATIONS));
    app.installTranslator(&translator);

    if(!QIcon::hasThemeIcon("reload"))
        QIcon::setThemeName("coastal");

    parse(argc, argv);

    SwitchView::start();
    QApplication::exec();

    PROGRAM_EXIT(0);
}

#ifdef  WIN32
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShow)
{
    int argc, pos;
    char **argv;
    argc = 1;
    size_t len = strlen(lpCmdLine);

    for (unsigned i = 0; i < len; i++) { 
        while (lpCmdLine[i] == ' ' && i < len)
            ++i;
        if (lpCmdLine[i] == '\"') {
            ++i; 
            while (lpCmdLine[i] != '\"' && i < len)
                ++i;  
        } 
        else while (lpCmdLine[i] != ' ' && i < len)
            ++i;  
        ++argc;
    } 

    argv = (char **)malloc(sizeof(char *) * (argc + 1));
    argv[0] = (char*)malloc(1024); 
    ::GetModuleFileName(0, argv[0], 1024); 

    for(unsigned i = 1; i < (unsigned)argc; i++) 
        argv[i] = (char*)malloc(len + 10); 

    argv[argc] = 0; 

    pos = 0;
    argc = 1;
    for (unsigned i = 0; i < len; i++) { 
        while (lpCmdLine[i] == ' ' && i < len)
            ++i;
        if (lpCmdLine[i] == '\"') {
            ++i; 
            while (lpCmdLine[i] != '\"' && i < len) { 
                argv[argc][pos] = lpCmdLine[i];
                ++i; 
                ++pos; 
            } 
        } 
        else { 
            while (lpCmdLine[i] != ' ' && i < len) { 
                argv[argc][pos] = lpCmdLine[i];
                ++i; 
                ++pos; 
            } 
        }
        argv[argc][pos] = 0;
        argc++; 
        pos = 0;  
    } 
    return main(argc, argv);
}
#endif
