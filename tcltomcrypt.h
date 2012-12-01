#ifndef _TCLTOMCRYPTH
#define _TCLTOMCRYPTH

#define ERRSTR(INTERP, STR)\
    Tcl_SetObjResult(INTERP, Tcl_NewStringObj(STR, -1));\
    return TCL_ERROR
struct TomcryptState;
typedef struct TomcryptState TomcryptState;
Tcl_HashTable* TomcryptHashTable(TomcryptState*);

int tomerr(Tcl_Interp *interp, int err);

#endif
