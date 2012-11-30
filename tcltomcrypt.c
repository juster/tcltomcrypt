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

void
Tomcrypt_Cleanup(ClientData cdata)
{
    Tomcrypt_State *state;
    Tcl_HashTable *symHash;
    int i;

    fprintf(stderr, "DBG: Tomcrypt_Cleanup\n");
    state = (Tomcrypt_State*)cdata;
    for(i=0; i<state->symHashCount; i++){
        fprintf(stderr, "DBG: deleting hash %d\n", i);
        Tcl_DeleteHashTable(state->symHashes+i);
    }
    Tcl_Free((char*)state);
}

int
Tomcrypt_Init(Tcl_Interp *interp)
{
    Tcl_Namespace *ns;
    Tomcrypt_State *state;
    int err;
    int i;

    if(Tcl_InitStubs(interp, TCL_VERSION, 0) == NULL){
        return TCL_ERROR;
    }

    state = (Tomcrypt_State*)Tcl_Alloc(sizeof(Tomcrypt_State));
    state->symHashCount = 0;
    ns = Tcl_CreateNamespace(interp, "tomcrypt",
        (ClientData)state, Tomcrypt_Cleanup);
    if((err = init_symmetric(interp, state)) != TCL_OK){
        Tcl_DeleteNamespace(ns);
        return err;
    }
    return TCL_OK;
}
