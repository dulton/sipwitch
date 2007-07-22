#ifndef _GNUTELEPHONY_DIGEST_H_
#define	_GNUTELEPHONY_DIGEST_H_

#ifndef	_UCOMMON_STRING_H_
#include <ucommon/string.h>
#endif

NAMESPACE_UCOMMON

class __EXPORT digest 
{
public:
	static unsigned md5(unsigned char *buf, const char *str);
	static unsigned md5(string &d, const char *str = NULL);
	static unsigned sha1(unsigned char *buf, const char *str);
	static unsigned sha1(string &d, const char *str = NULL);
	static unsigned rmd160(unsigned char *buf, const char *str);
	static unsigned rmd160(string &d, const char *str = NULL);
};

END_NAMESPACE

#endif
