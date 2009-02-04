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

%extend Calls {
#ifdef  SWIGPYTHON
    char *__str__() {
        static char temp[256];
        if(self->active)
            snprintf(temp, sizeof(temp), "%s %s %s %u",
                self->sid, self->source, self->target, self->active);
        else
            snprintf(temp, sizeof(temp), "%s %s %u",
                self->sid, self->source, self->started);
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
        snprintf(temp, sizeof(temp), "%s %d", self->id, self->members);
        for(unsigned entry = 0; entry < 2; ++entry) {
            len = strlen(temp);
            snprintf(temp + len, sizeof(temp) - len, " %lu %hu %hu",
                self->data[entry].total, self->data[entry].peak, self->data[entry].current);
        }
        len = strlen(temp);
        snprintf(temp + len, sizeof(temp) - len, " %lu", self->lastcall);
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
        snprintf(temp, sizeof(temp), "%s %d", self->id, self->members);
        for(unsigned entry = 0; entry < 2; ++entry) {
            len = strlen(temp);
            snprintf(temp + len, sizeof(temp) - len, " %lu %hu %hu",
                self->period[entry].total, self->period[entry].min, self->period[entry].max);
        }
        len = strlen(temp);
        snprintf(temp + len, sizeof(temp) - len, " %lu", self->lastcall);
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

