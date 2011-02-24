// Copyright (C) 2010 David Sugar, Tycho Softworks.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#include <ucommon/ucommon.h>
#include <ucommon/secure.h>
#include <sipwitch/sipwitch.h>
#include <config.h>
#ifdef  HAVE_PWD_H
#include <pwd.h>
#endif

using namespace UCOMMON_NAMESPACE;
using namespace SIPWITCH_NAMESPACE;

extern "C" int main(int argc, char **argv)
{
    char *realm = NULL, *secret, *verify;
    const char *mode = "md5";
    char buffer[128];
    char replace[128];
    string_t digestbuf;
    fpos_t pos;
    FILE *fp;

#ifdef  _MSWINDOWS_
    const char *control = "\\\\.\\mailslot\\sipwitch_ctrl";
#else
    const char *control = DEFAULT_VARPATH "/run/sipwitch/control";
#endif

    const char *user = *(++argv);

    if(String::equal(user, "-version")) {
        printf("sippasswd 0.1\n"
            "Copyright (C) 2010 David Sugar, Tycho Softworks\n"
            "License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>\n"
            "This is free software: you are free to change and redistribute it.\n"
            "There is NO WARRANTY, to the extent permitted by law.\n");
        exit(0);
    }

#ifdef  HAVE_PWD_H
    if(user && getuid() != 0) {
        fprintf(stderr, "*** sippasswd: only root can change other user's digests\n");
        exit(1);
    }
    if(!user) {
        struct passwd *pwd = getpwuid(getuid());
        if(!pwd) {
            fprintf(stderr, "*** sippasswd: user id cannot be determined\n");
            exit(3);
        }
        user = strdup(pwd->pw_name);
    }
    if(geteuid() != 0) {
        fprintf(stderr, "*** sippasswd: root privilege required\n");
        exit(3);
    }
#else
    if(!user) {
        fprintf(stderr, "*** sippasswd: user id not specified\n");
        exit(3);
    }
#endif

    fsys_t fs;
    fsys::open(fs, DEFAULT_CFGPATH "/siprealm", fsys::ACCESS_RDONLY);

    if(!is(fs))
        fsys::open(fs, DEFAULT_VARPATH "/lib/sipwitch/uuid", fsys::ACCESS_RDONLY);

    if(!is(fs)) {
        fprintf(stderr, "*** sippasswd: no realm active\n");
        exit(4);
    }
    memset(buffer, 0, sizeof(buffer));
    fsys::read(fs, buffer, sizeof(buffer) - 1);
    fsys::close(fs);

    char *cp = strchr(buffer, '\n');
    if(cp)
        *cp = 0;

    cp = strchr(buffer, ':');
    if(cp)
        *(cp++) = 0;

    if(cp && *cp)
        mode = cp;

    realm = strdup(buffer);
    secret = getpass("Enter new SIP secret: ");
    if(!secret || !*secret) {
        printf("no password supplied\n");
        exit(0);
    }

    verify = getpass("Retype new SIP secret: ");
    if(!verify || !*verify || !String::equal(secret, verify)) {
        printf("sorry, secrets do not match\n");
        exit(0);
    }

    digest_t digest = mode;

    if(!digest.puts((string_t)user + ":" + (string_t)realm + ":" + (string_t)secret))
        shell::errexit(1, "*** sippasswd: cannot compute");
    else
        digestbuf = *digest;

    snprintf(replace, sizeof(replace), "%s:%s\n", user, *digestbuf);

    // create work directory if it does not exist
    fsys::createDir(DEFAULT_VARPATH "/lib/sipwitch", 0770);

    // make sure always created root only
    fsys::create(fs, DEFAULT_VARPATH "/lib/sipwitch/digests.db",
        fsys::ACCESS_RDONLY, 0600);
    fsys::close(fs);

    fp = fopen(DEFAULT_VARPATH "/lib/sipwitch/digests.db", "r+");
    if(!fp) {
        fprintf(stderr, "*** sippasswd: cannot access digest");
        exit(1);
    }

    for(;;) {
        fgetpos(fp, &pos);
        if(NULL == fgets(buffer, sizeof(buffer), fp) || feof(fp))
            break;

        if(String::equal(buffer, replace)) {
            fclose(fp);
            printf("digest unchanged\n");
            exit(0);
        }

        cp = strchr(buffer, ':');
        if(!cp)
            continue;

        *cp = 0;
        if(String::equal(buffer, user))
            break;
    }

    // update digest file
    fsetpos(fp, &pos);
    fputs(replace, fp);
    fclose(fp);

    // if server is up, also sync server with digest change...
    fp = fopen(control, "w");
    if(fp) {
        fprintf(fp, "digest %s %s\n", user, *digestbuf);
        fclose(fp);
    }

    printf("digest updated\n");
    exit(0);
}

