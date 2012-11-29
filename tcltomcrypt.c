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

int
Tomcrypt_Init(Tcl_Interp *interp)
{
    int err;

    if(Tcl_InitStubs(interp, TCL_VERSION, 0) == NULL){
        return TCL_ERROR;
    }
    if((err = init_symmetric(interp)) != TCL_OK){
        return err;
    }
    return TCL_OK;
}
