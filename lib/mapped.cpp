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

#include <config.h>
#include <gnutelephony/mapped.h>

#include <fcntl.h>
#include <ctype.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>

#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#include <sys/types.h>
#endif

#if HAVE_FTOK
#include <sys/ipc.h>
#include <sys/shm.h>
#endif

#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <limits.h>

#if	defined(HAVE_FTOK) && !defined(HAVE_SHM_OPEN)

static void ftok_name(const char *name, char *buf, size_t max)
{
	struct stat ino;
	if(*name == '/')
		++name;

	if(!stat("/var/run/ipc", &ino) && S_ISDIR(ino.st_mode))
		snprintf(buf, sizeof(buf), "/var/run/ipc/%s", name);
	else
		snprintf(buf, sizeof(buf), "/tmp/.%s.ipc", name);
}

static key_t createipc(const char *name, char mode)
{
	char buf[65];
	int fd;

	ftok_name(name, buf, sizeof(buf));
	fd = open(buf, O_CREAT | O_EXCL | O_WRONLY, 0660);
	if(fd > -1)
		close(fd);
	return ftok(buf, mode);
}

static key_t accessipc(const char *name, char mode)
{
	char buf[65];

	ftok_name(name, buf, sizeof(buf));
	return ftok(buf, mode);
}

#endif

using namespace UCOMMON_NAMESPACE;

MappedMemory::MappedMemory(const char *fn, size_t len)
{
	create(fn, size);
}

MappedMemory::MappedMemory(const char *fn)
{
	create(fn, 0);
}

MappedMemory::MappedMemory()
{
	size = 0;
	used = 0;
	map = NULL;
}

#if defined(_MSWINDOWS_)

void MappedMemory::create(const char *fn, size_t len)
{
	int share = FILE_SHARE_READ;
	int prot = FILE_MAP_READ;
	int mode = GENERIC_READ;
	struct stat ino;

	size = 0;
	used = 0;
	map = NULL;

	if(*fn == '/')
		++fn;

	if(len) {
		prot = FILE_MAP_WRITE;
		mode |= GENERIC_WRITE;
		share |= FILE_SHARE_WRITE;
		fd = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, len, fn);
	}
	else
		fd = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, fn);
	
	if(fd == INVALID_HANDLE_VALUE || fd == NULL) 
		return;

	map = (caddr_t)MapViewOfFile(fd, FILE_MAP_ALL_ACCESS, 0, 0, len);
	if(map) {
		size = len;
		VirtualLock(map, size);
	}
}

MappedMemory::~MappedMemory()
{
	release();
}

void MappedMemory::remove(const char *id)
{
}

void MappedMemory::release(void)
{
	if(map) {
		VirtualUnlock(map, size);
		UnmapViewOfFile(fd);
		CloseHandle(fd);
		map = NULL;
		fd = INVALID_HANDLE_VALUE;
	}
}

#elif defined(HAVE_SHM_OPEN)

void MappedMemory::create(const char *fn, size_t len)
{
	int prot = PROT_READ;
	struct stat ino;
	char fbuf[65];

	size = 0;
	used = 0;

	if(*fn != '/') {
		snprintf(fbuf, sizeof(fbuf), "/%s", fn);
		fn = fbuf;
	}
	
	if(len) {
		prot |= PROT_WRITE;
		fd = shm_open(fn, O_RDWR | O_CREAT, 0660);
		if(fd > -1)
			ftruncate(fd, len);
	}
	else {
		fd = shm_open(fn, O_RDONLY, 0660);
		if(fd > -1) {
			fstat(fd, &ino);
			len = ino.st_size;
		}
	}

	if(fd < 0)
		return;

	map = (caddr_t)mmap(NULL, len, prot, MAP_SHARED, fd, 0);
	close(fd);
	if(map != (caddr_t)MAP_FAILED) {
		size = len;
		mlock(map, size);
	}
}

MappedMemory::~MappedMemory()
{
	release();
}

void MappedMemory::release()
{
	if(size) {
		munlock(map, size);
		munmap(map, size);
		size = 0;
	}
}

void MappedMemory::remove(const char *fn)
{
	char fbuf[65];

	if(*fn != '/') {
		snprintf(fbuf, sizeof(fbuf), "/%s", fn);
		fn = fbuf;
	}

	shm_unlink(fn);
}

#else

void MappedMemory::remove(const char *name)
{
	key_t key;
	fd_t fd;

	key = accessipc(name, 'S');
	if(key) {
        fd = shmget(key, 0, 0);
        if(fd > -1)
			shmctl(fd, IPC_RMID, NULL);
	}
}

MappedMemory::MappedMemory(const char *name, size_t len)
{
	struct shmid_ds stat;
	size = 0;
	used = 0;
	key_t key;

	if(len) {
		key = createipc(name, 'S');
remake:
		fd = shmget(key, len, IPC_CREAT | IPC_EXCL | 0660);
		if(fd == -1 && errno == EEXIST) {
			fd = shmget(key, 0, 0);
			if(fd > -1) {
				shmctl(fd, IPC_RMID, NULL);
				goto remake;
			}
		}
	}
	else {
		key = accessipc(name, 'S');
		fd = shmget(key, 0, 0);
	}
	
	if(fd > -1) {
		if(len)
			size = len;
		else if(shmctl(fd, IPC_STAT, &stat) == 0)
			size = stat.shm_segsz;
		else
			fd = -1;
	}
	map = (caddr_t)shmat(fd, NULL, 0);
#ifdef	SHM_LOCK
	if(fd > -1)
		shmctl(fd, SHM_LOCK, NULL);
#endif
}

MappedMemory::~MappedMemory()
{
	release();
}

void MappedMemory::release(void)
{
	if(size > 0) {
#ifdef	SHM_UNLOCK
		shmctl(fd, SHM_UNLOCK, NULL);
#endif
		shmdt(map);
		fd = -1;
		size = 0;
	}
}

#endif

void MappedMemory::fault(void) 
{
	abort();
}

void *MappedMemory::sbrk(size_t len)
{
	void *mp = (void *)(map + used);
	if(used + len > size)
		fault();
	used += len;
	return mp;
}
	
void *MappedMemory::offset(size_t offset)
{
	if(offset >= size)
		fault();
	return (void *)(map + offset);
}

MappedReuse::MappedReuse(const char *name, size_t osize, unsigned count) :
ReusableAllocator(), MappedMemory(name,  osize * count)
{
	objsize = osize;
	reading = 0;
}

MappedReuse::MappedReuse(size_t osize) :
ReusableAllocator(), MappedMemory()
{
	objsize = osize;
	reading = 0;
}

bool MappedReuse::avail(void)
{
	bool rtn = false;
	lock();
	if(freelist || used < size)
		rtn = true;
	unlock();
	return rtn;
}

ReusableObject *MappedReuse::request(void)
{
    ReusableObject *obj = NULL;

	lock();
	if(freelist) {
		obj = freelist;
		freelist = next(obj);
	} 
	else if(used + objsize <= size)
		obj = (ReusableObject *)sbrk(objsize);
	unlock();
	return obj;	
}

ReusableObject *MappedReuse::get(void)
{
	return getTimed(Timer::inf);
}

void MappedReuse::removeLocked(ReusableObject *obj)
{
	LinkedObject **ru = (LinkedObject **)freelist;
	obj->retain();
	obj->enlist(ru);
}

ReusableObject *MappedReuse::getLocked(void)
{
	ReusableObject *obj = NULL;

	if(freelist) {
		obj = freelist;
		freelist = next(obj);
	}
	else if(used + objsize <= size)
		obj = (ReusableObject *)sbrk(objsize);

	return obj;
}

ReusableObject *MappedReuse::getTimed(timeout_t timeout)
{
	bool rtn = true;
	Timer expires;
	ReusableObject *obj = NULL;

	if(timeout && timeout != Timer::inf)
		expires.set(timeout);

	lock();
	while(rtn && (!freelist || freelist && reading) && used >= size) {
		++waiting;
		if(timeout == Timer::inf)
			wait();
		else if(timeout)
			rtn = wait(*expires);
		else
			rtn = false;
		--waiting;
	}
	if(!rtn) {
		unlock();
		return NULL;
	}
	if(freelist) {
		obj = freelist;
		freelist = next(obj);
	}
	else if(used + objsize <= size)
		obj = (ReusableObject *)sbrk(objsize);
	unlock();
	return obj;
}

