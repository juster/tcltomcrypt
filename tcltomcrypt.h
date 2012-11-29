#ifndef _TCLTOMCRYPTH
#define _TCLTOMCRYPTH

#define ERRSTR(INTERP, STR)\
    Tcl_SetObjResult(INTERP, Tcl_NewStringObj(STR, -1));\
    return TCL_ERROR

typedef struct _TCcipher {
    char cmd[128];
    int idx;
    symmetric_key skey;
} TCcipher;

typedef int subcmdproc(const char *, TCcipher *, Tcl_Interp *, int, Tcl_Obj * const *);

struct subcmd {
    char *name;
    subcmdproc *proc;
};

int tomerr(Tcl_Interp *interp, int err);

#endif
