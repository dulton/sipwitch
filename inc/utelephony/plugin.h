#ifndef _GNUTELEPHONY_PLUGIN_H_
#define	_GNUTELEPHONY_PLUGIN_H_

#ifndef _UCOMMON_LINKED_H_
#include <ucommon/linked.h>
#endif

#ifndef	_UCOMMON_THREAD_H_
#include <ucommon/thread.h>
#endif

#ifndef	_UCOMMON_STRING_H_
#include <ucommon/string.h>
#endif

NAMESPACE_UCOMMON

class __EXPORT plugin
{
public:
	class __EXPORT authorize : protected service::callback
	{
	protected:
		friend class plugin;

		inline authorize() : callback(1, "authorize") {};

		virtual ~authorize();

		virtual bool authenticate(const char *uid, const char *secret) = 0;
    };

	static bool authenticate(const char *uid, const char *secret);
};

END_NAMESPACE

#endif
