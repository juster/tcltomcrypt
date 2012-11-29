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

typedef int cipherproc(const char *, TCcipher *, Tcl_Interp *, int, Tcl_Obj * const *);

int tomerr(Tcl_Interp *interp, int err);

#endif
