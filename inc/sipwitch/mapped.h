// Copyright (C) 2006-2007 David Sugar, Tycho Softworks.
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

/**
 * Support for memory mapped objects.
 * Memory mapped objects are used to publish GNU Telephony services state
 * information and statistics so that it may be accessible by external
 * management processes.  The mapped memory objects are usually treated as
 * a UCommon vector or reusable type factory, in the latter case using the
 * shared memory block itself as a local heap.  Memory access is managed
 * through a form of shared locking formed through conditionals.
 * @file gnutelephony/mapped.h
 */

#ifndef _SIPWITCH_MAPPED_H_
#define	_SIPWITCH_MAPPED_H_

#ifndef _UCOMMON_LINKED_H_
#include <ucommon/linked.h>
#endif

#ifndef	_UCOMMON_THREAD_H_
#include <ucommon/thread.h>
#endif

#ifndef	_UCOMMON_STRING_H_
#include <ucommon/string.h>
#endif

#ifndef	_MSWINDOWS_
#include <signal.h>
#endif

NAMESPACE_UCOMMON

class __EXPORT MappedMemory
{
private:
	caddr_t map;
	fd_t fd;	

protected:
	size_t size, used;

	virtual void fault(void);

public:
	MappedMemory(const char *fname, size_t len);
	MappedMemory(const char *fname);
	MappedMemory();
	virtual ~MappedMemory();

	void create(const char *fname, size_t len = (size_t)0);
	void release(void);

	static	void remove(const char *id);

	inline operator bool() const
		{return (size != 0);};

	inline bool operator!() const
		{return (size == 0);};

	void *sbrk(size_t size);
	void *offset(size_t offset);

	inline size_t len(void)
		{return size;};

	inline caddr_t getStart(void)
		{return map;};
};

class __EXPORT MappedReuse : protected ReusableAllocator, protected MappedMemory
{
private:
	unsigned objsize;
	unsigned reading;
	mutex_t mutex;

public:
	MappedReuse(const char *name, size_t osize, unsigned count);
	MappedReuse(size_t osize);

	inline void create(const char *fname, unsigned count)
		{MappedMemory::create(fname, count * objsize);};

	bool avail(void);
	ReusableObject *request(void);
	ReusableObject *get(void);
	ReusableObject *getTimed(timeout_t timeout);
	ReusableObject *getLocked(void);
	void removeLocked(ReusableObject *obj);	
};

template <class T>
class mapped_array : public MappedMemory
{
public:
	inline mapped_array(const char *fn, unsigned members) : 
		MappedMemory(fn, members * sizeof(T)) {};

	inline mapped_array() : MappedMemory() {};

	inline void create(const char *fn, unsigned members)
		{MappedMemory::create(fn, members * sizeof(T));};

	inline void initialize(void)
		{new((caddr_t)offset(0)) T[size / sizeof(T)];};

	inline void addLock(void)
		{sbrk(sizeof(T));};
	
	inline T *operator()(unsigned idx)
		{return static_cast<T*>(offset(idx * sizeof(T)));}

	inline T *operator()(void)
		{return static_cast<T*>(sbrk(sizeof(T)));};
	
	inline T &operator[](unsigned idx)
		{return *(operator()(idx));};

	inline unsigned getSize(void)
		{return (unsigned)(size / sizeof(T));};
};

template <class T>
class mapped_reuse : public MappedReuse
{
public:
	inline mapped_reuse(const char *fname, unsigned count) :
		MappedReuse(fname, sizeof(T), count) {};

	inline mapped_reuse() :
		MappedReuse(sizeof(T)) {};

	inline void initialize(void)
		{new((caddr_t)pos(0)) T[size / sizeof(T)];};

	inline operator bool()
		{return MappedReuse::avail();};

	inline bool operator!()
		{return !MappedReuse::avail();};

	inline operator T*()
		{return mapped_reuse::get();};

	inline T* operator*()
		{return mapped_reuse::get();};

	inline T *pos(size_t idx)
		{return static_cast<T*>(MappedReuse::offset(idx * sizeof(T)));};

	inline T *get(void)
		{return static_cast<T*>(MappedReuse::get());};

    inline T *getTimed(timeout_t timeout)
        {return static_cast<T*>(MappedReuse::getTimed(timeout));};

	inline T *request(void)
		{return static_cast<T*>(MappedReuse::request());};

	inline void removeLocked(T *obj)
		{MappedReuse::removeLocked(obj);};

	inline T *getLocked(void)
		{return static_cast<T*>(MappedReuse::getLocked());};

	inline void release(T *o)
		{ReusableAllocator::release(o);};
};
	
template <class T>
class mapped_view : protected MappedMemory
{
public:
	inline mapped_view(const char *fn) : 
		MappedMemory(fn) {};
	
	inline volatile const T *operator()(unsigned idx)
		{return static_cast<const T*>(offset(idx * sizeof(T)));}
	
	inline volatile const T &operator[](unsigned idx)
		{return *(operator()(idx));};

	inline unsigned getCount(void)
		{return (unsigned)(size / sizeof(T));};
};

END_NAMESPACE

#endif
