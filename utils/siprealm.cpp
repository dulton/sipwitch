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
#include <sipwitch/digest.h>
#include <config.h>

using namespace UCOMMON_NAMESPACE;
using namespace SIPWITCH_NAMESPACE;

static void usage(void)
{
	fprintf(stderr, "usage: siprealm [[-md5|-rmd160|-sha1] [\"realm\"]]\n"
		"[options]\n"
		"  -md5                 specify md5 computation\n"
		"  -rmd160              specify rmd160 computation\n"
		"  -sha1                specify sha1 computation\n"
		"Report bugs to sipwitch-devel@gnu.org\n");
	exit(3);
}

static void show(void)
{
	fsys_t fs;
	char buffer[256];

	fsys::open(fs, "/etc/siprealm", fsys::ACCESS_RDONLY);
	if(!is(fs)) {
error:
		fprintf(stderr, "*** sipdigest: no realm known\n");
        exit(1);
    }

	memset(buffer, 0, sizeof(buffer));
	fsys::read(fs, buffer, sizeof(buffer) - 1);
	fsys::close(fs);
	char *cp = strchr(buffer, ':');
	if(cp)
		*cp = 0;

	if(!buffer[0])
		goto error;

	printf("%s\n", buffer);
	exit(0);
}

extern "C" int main(int argc, char **argv)
{
	char *realm = NULL;
	const char *mode = NULL;
	fsys_t fs;
	char buffer[256];
	char replace[256];
	char *cp = NULL;
	FILE *fp;

#ifdef	_MSWINDOWS_
	const char *control = "\\\\.\\mailslot\\sipwitch_ctrl";
#else
	const char *control = DEFAULT_VARPATH "/run/sipwitch/control";
#endif

	++argv;
	if(!*argv)
		show();

	if(!strncmp(*argv, "--", 2))
		++*argv;

	if(!strcmp(*argv, "-version")) {
		printf("siprealm 0.1\n"
			"Copyright (C) 2008 David Sugar, Tycho Softworks\n"
			"License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>\n"
			"This is free software: you are free to change and redistribute it.\n"
			"There is NO WARRANTY, to the extent permitted by law.\n");
		exit(0);
	}

	if(String::equal(*argv, "-md5")) {
		mode = "md5";
		++argv;
	}
	else if(String::equal(*argv, "-sha1")) {
		mode = "sha1";
		++argv;
	}
	else if(String::equal(*argv, "-rmd160")) {
		mode = "rmd160";
		++argv;
	}
	else if(String::equal(*argv, "-?") || String::equal(*argv, "-help"))
		usage();
	else if(**argv == '-') {
		fprintf(stderr, "*** %s: unknown digest mode", *argv);
		exit(2);
	}

	fsys::open(fs, "/etc/siprealm", fsys::ACCESS_RDONLY);
	memset(buffer, 0, sizeof(buffer));
	if(is(fs)) {
		fsys::read(fs, buffer, sizeof(buffer) - 1);
		fsys::close(fs);
		cp = strchr(buffer, ':');
		if(cp)
			*(cp++) = 0;
	}

	realm = *argv;
	if(!realm)
		realm = buffer;
	else if(argv[1] || *realm == '-')
		usage();

	if(!cp || !*cp)
		cp = (char *)"md5";

	// make sure we have a valid mode, default is md5...
	if(!mode && cp && *cp)
		mode = cp;

	if(!mode)
		mode = "md5";

	// if unchanged, we leave alone...
	if(String::equal(buffer, realm) && String::equal(cp, mode))
		goto exit;

	// create replacement realm string...
	if(String::equal(mode, "md5"))
		String::set(replace, sizeof(replace), realm);
	else
		snprintf(replace, sizeof(replace), "%s:%s", realm, mode);

	::remove("/etc/siprealm");
	fsys::create(fs, "/etc/siprealm", fsys::ACCESS_WRONLY, 0644);
	if(is(fs)) {
		fsys::write(fs, replace, strlen(replace));
		fsys::close(fs);
	}
	else {
		fprintf(stderr, "*** siprealm: root permission required\n");
		exit(0);
	}				

	// if previous digests cached, clear them as they are now invalid...
	::remove(DEFAULT_VARPATH "/lib/sipwitch/digests.db");

	// if server is up, also sync server with realm change...
	fp = fopen(control, "w");
	if(fp) {
		fprintf(fp, "realm %s\n", realm);
		fclose(fp);
	}

exit:
	printf("%s\n", realm);
	exit(0);
}

