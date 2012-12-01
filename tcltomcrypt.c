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

static void
TomcryptCleanup(ClientData cdata)
{
    TomcryptState *state;
    Tcl_HashTable *cipherHash;
    int i;

    fprintf(stderr, "DBG: TomcryptCleanup\n");
    state = (TomcryptState*)cdata;
    for(i=0; i<state->cipherHashCount; i++){
        fprintf(stderr, "DBG: deleting hash %d\n", i);
        Tcl_DeleteHashTable(state->cipherHashes+i);
    }
    Tcl_Free((char*)state);
}

int
Tomcrypt_Init(Tcl_Interp *interp)
{
    Tcl_Namespace *ns;
    TomcryptState *state;
    int err;
    int i;

    if(Tcl_InitStubs(interp, TCL_VERSION, 0) == NULL){
        return TCL_ERROR;
    }
    if(Tcl_PkgProvide(interp, "tomcrypt", "0.01") != TCL_OK){
        return TCL_ERROR;
    }

    state = (TomcryptState*)Tcl_Alloc(sizeof(TomcryptState));
    state->cipherHashCount = 0;
    ns = Tcl_CreateNamespace(interp, "::tomcrypt",
        (ClientData)state, TomcryptCleanup);
    if((err = initCiphers(interp, state)) != TCL_OK){
        Tcl_DeleteNamespace(ns);
        return err;
    }
    return TCL_OK;
}
