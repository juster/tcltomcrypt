#ifndef _TCLTOMCRYPTH
#define _TCLTOMCRYPTH

#define ERRSTR(INTERP, STR)\
    Tcl_SetObjResult(INTERP, Tcl_NewStringObj(STR, -1));\
    return TCL_ERROR

typedef struct TomcryptState {
    int cipherHashCount;
    Tcl_HashTable cipherHashes[TAB_SIZE]; /* TAB_SIZE from tomcrypt.h */
} TomcryptState;

int tomerr(Tcl_Interp *interp, int err);

#endif
