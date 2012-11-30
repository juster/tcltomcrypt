#include <stdio.h>
#include <tcl.h>
#include <tomcrypt.h>
#include "tcltomcrypt.h"

int
tomerr(Tcl_Interp *interp, int err)
{
    Tcl_Obj *obj;
    obj = Tcl_NewStringObj(error_to_string(err), -1);
    Tcl_SetObjResult(interp, obj);
    return TCL_ERROR;
}

typedef struct Tomcrypt_State {
    Tcl_HashTable symHash;
} Tomcrypt_State;

void
Tomcrypt_Cleanup(ClientData cdata)
{
    Tomcrypt_State *state;
    state = (Tomcrypt_State*)cdata;
    /* TODO: free symmetric keys in symHash hash table */
    Tcl_DeleteHashTable(&state->symHash);
    Tcl_Free((char*)cdata);
}

int
Tomcrypt_Init(Tcl_Interp *interp)
{
    Tcl_Namespace *ns;
    Tomcrypt_State *state;
    int err;

    if(Tcl_InitStubs(interp, TCL_VERSION, 0) == NULL){
        return TCL_ERROR;
    }

    state = (Tomcrypt_State*)Tcl_Alloc(sizeof(Tomcrypt_State));
    Tcl_InitHashTable(&state->symHash, TCL_STRING_KEYS);

    ns = Tcl_CreateNamespace(interp, "tomcrypt", (ClientData)state, Tomcrypt_Cleanup);

    if((err = init_symmetric(interp, &state->symHash)) != TCL_OK){
        Tcl_DeleteNamespace(ns);
        return err;
    }
    return TCL_OK;
}
