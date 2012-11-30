#ifndef _TCLTOMCRYPTH
#define _TCLTOMCRYPTH

#define ERRSTR(INTERP, STR)\
    Tcl_SetObjResult(INTERP, Tcl_NewStringObj(STR, -1));\
    return TCL_ERROR

typedef struct Tomcrypt_State {
    int symHashCount;
    Tcl_HashTable symHashes[TAB_SIZE]; /* TAB_SIZE from tomcrypt.h */
} Tomcrypt_State;

int tomerr(Tcl_Interp *interp, int err);

#endif
