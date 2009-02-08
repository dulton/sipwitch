%define DOCSTRING
"Interface package for GNU SIP Witch.

This allows one to control and manage a locally running instance of GNU
SIP Witch.  Access to registration information and server statistics is also
offered."
%enddef

%module(docstring=DOCSTRING) sipwitch
%{
#include <sipwitch/stats.h>
#include "swig.h"
#include "swig.cpp"
%}

%immutable;
%nodefaultctor;
%feature("autodoc", "1");

%include swig.h

%extend Users {
#ifdef  SWIGPYTHON
    char *__str__() {
        static char temp[512];
        snprintf(temp, sizeof(temp), "%s,%s,%s,%s,%s,%u,%u",
            self->status, self->userid, self->extension, self->display, self->service, self->trs, self->active);
        return temp;
    }
#endif
    Users(unsigned ext) {
        Users *u;
        u = (Users *)malloc(sizeof(Users));
        getextension(u, ext);
        return u;
    }
    Users(const char *id) {
        Users *u;
        u = (Users *)malloc(sizeof(Users));
        getuserid(u, id);
        return u;
    }
    ~Users() {
        free($self);
    }
}

%extend Calls {
#ifdef  SWIGPYTHON
    char *__str__() {
        static char temp[256];
        if(self->active)
            snprintf(temp, sizeof(temp), "%s,%s,%s,%s,%s,%u",
                self->sid, self->state, self->source, self->display, self->target, self->active);
        else
            snprintf(temp, sizeof(temp), "%s,%s,%s,%s,,%u",
                self->sid, self->state, self->source, self->display, self->started);
        return temp;
    }
#endif
    Calls(unsigned index) {
        Calls *c;
        c = (Calls *)malloc(sizeof(Calls));
        getcalls(c, index);
        return c;
    }

    Calls(const char *sid) {
        Calls *c;
        c = (Calls *)malloc(sizeof(Calls));
        getcallsbyid(c, sid);
        return c;
    }

    ~Calls() {
        free($self);
    }
}

%extend Stats {
#ifdef  SWIGPYTHON
    char *__str__() {
        static char temp[256];
        size_t len;
        snprintf(temp, sizeof(temp), "%s,%d", self->id, self->members);
        for(unsigned entry = 0; entry < 2; ++entry) {
            len = strlen(temp);
            snprintf(temp + len, sizeof(temp) - len, ",%lu,%hu,%hu",
                self->data[entry].total, self->data[entry].peak, self->data[entry].current);
        }
        len = strlen(temp);
        snprintf(temp + len, sizeof(temp) - len, ",%lu", self->lastcall);
        return temp;
    }
#endif
    Stats(unsigned index) {
        Stats *s;
        s = (Stats *)malloc(sizeof(Stats));
        getstats(s, index);
        return s;
    }

    ~Stats() {
        free($self);
    }

    unsigned active() {
        return self->data[0].current + self->data[1].current;
    }
};

%extend PStats {
#ifdef  SWIGPYTHON
    char *__str__() {
        static char temp[256];
        size_t len;
        snprintf(temp, sizeof(temp), "%s,%d", self->id, self->members);
        for(unsigned entry = 0; entry < 2; ++entry) {
            len = strlen(temp);
            snprintf(temp + len, sizeof(temp) - len, ",%lu,%hu,%hu",
                self->period[entry].total, self->period[entry].min, self->period[entry].max);
        }
        len = strlen(temp);
        snprintf(temp + len, sizeof(temp) - len, ",%lu", self->lastcall);
        return temp;
    }
#endif
    PStats(unsigned index) {
        PStats *s;
        s = (PStats *)malloc(sizeof(PStats));
        getpstats(s, index);
        return s;
    }

    ~PStats() {
        free($self);
    }
};

#ifdef  SWIGPYTHON
%typemap(out) char ** {
  int len,i;
  len = 0;
  while ($1[len]) len++;
  $result = PyList_New(len);
  for (i = 0; i < len; i++) {
    PyList_SetItem($result,i,PyString_FromString($1[i]));
  }
}
#endif

%include exception.i

%exception {
    lock();

    $function

    switch(error_code) {
    case ERR_NOATTACH:
        SWIG_exception(SWIG_RuntimeError , "sipwitch offline"); 
        break;
    case ERR_INVSTATS:
        SWIG_exception(SWIG_IndexError, "invalid stats index");
        break;
    case ERR_INVCALLS:
        SWIG_exception(SWIG_IndexError, "invalid calls index");
        break;
    case ERR_NOTFOUND:
        SWIG_exception(SWIG_ValueError, "user not found");
        break;
    case ERR_TIMEOUT:
        SWIG_exception(SWIG_IOError, "control timeout");
        break;
    case ERR_REQUEST:
        SWIG_exception(SWIG_UnknownError, "request failed");
        break;
    default:
        break;
    };

    unlock();
}

// return last error.  for use when exceptions are not supported.
int error();

// attach to sipwitch daemon.  ignored if already attached.  exception if fails.
void attach();

// disconnect from running sipwitch daemon
void release();

// initialize and check if online without throwing an exception
bool check();
   
// call generic control interface with a command
int control(char *command); 

// count active calls
unsigned count();

// get range of stat nodes, for python loops...
char **statrange();

// get list of users, for python loops...
char **users();

// get list of calls, for python loops...
char **calls();
