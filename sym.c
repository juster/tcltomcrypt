#include <tcl.h>
#include <tomcrypt.h>
#include "tcltomcrypt.h"

static int
cipher_done(const char *subcmd, TCcipher *sym, Tcl_Interp *interp,
            int objc, Tcl_Obj * const *objv)
{
    Tcl_DeleteCommand(interp, sym->cmd);
    return TCL_OK;
}

static int
cipher_endecrypt(const char *subcmd, TCcipher *sym, Tcl_Interp *interp,
                 int objc, Tcl_Obj * const *objv)
{
    Tcl_Obj *text;
    unsigned char *buf;
    int blocklen;
    int len;
    int err;

    if(objc != 3){
        Tcl_WrongNumArgs(interp, 2, objv, "varname");
        return TCL_ERROR;
    }

    text = Tcl_ObjGetVar2(interp, objv[2], NULL, TCL_LEAVE_ERR_MSG);
    if(text == NULL){
        return TCL_ERROR;
    }
    buf = Tcl_GetByteArrayFromObj(text, &len);
    blocklen = cipher_descriptor[sym->idx].block_length;
    if(len < blocklen){
        Tcl_SetObjResult(interp,
            Tcl_ObjPrintf("var named %s is shorter than blocksize %d",
                Tcl_GetString(objv[2]),
                blocklen));
        return TCL_ERROR;
    }

    if(subcmd[3] == 'E'){
        err = cipher_descriptor[sym->idx].ecb_encrypt(buf, buf, &sym->skey);
    }else{
        err = cipher_descriptor[sym->idx].ecb_decrypt(buf, buf, &sym->skey);
    }
    Tcl_InvalidateStringRep(text);
    if(err != CRYPT_OK){
        return tomerr(interp, err);
    }

    return TCL_OK;
}

static int
cipher_keysize(const char *subcmd, TCcipher *sym, Tcl_Interp *interp,
                 int objc, Tcl_Obj * const *objv)
{
    int size;
    int err;

    if(objc != 3){
        Tcl_SetObjResult(interp,
            Tcl_ObjPrintf("wrong # args: should be $key keySize num"));
        return TCL_ERROR;
    }
    if(Tcl_GetIntFromObj(interp, objv[2], &size) != TCL_OK){
        return TCL_ERROR;
    }
    if((err = cipher_descriptor[sym->idx].keysize(&size)) != CRYPT_OK){
        return tomerr(interp, err);
    }
    Tcl_SetObjResult(interp, Tcl_NewIntObj(size));
    return TCL_OK;
}

static int
cipher_test(const char *subcmd, TCcipher *sym, Tcl_Interp *interp,
            int objc, Tcl_Obj * const *objv)
{
    int err;
    if((err = cipher_descriptor[sym->idx].test()) != CRYPT_OK){
        return tomerr(interp, err);
    }
    return TCL_OK;
}

const char *cipher_cmds[] = {
    "done",
    "ecbEncrypt",
    "ecbDecrypt",
    "keySize",
    "test",
    NULL,
};

cipherproc *cipher_procs[] = {
    cipher_done,
    cipher_endecrypt,
    cipher_endecrypt,
    cipher_keysize,
    cipher_test,
};

static int
Cipher_Ensemble(ClientData cdata, Tcl_Interp *interp,
    int objc, Tcl_Obj *const objv[])
{
    TCcipher *sym;
    int idx;

    if(Tcl_GetIndexFromObj(interp, objv[1], cipher_cmds,
        "cipher command", TCL_EXACT, &idx) == TCL_ERROR){
        return TCL_ERROR;
    }
    sym = (TCcipher*)cdata;
    return cipher_procs[idx](Tcl_GetString(objv[1]), sym, interp, objc, objv);
}

static void
Cipher_Cleanup(ClientData cdata)
{
    TCcipher *sym;
    sym = (TCcipher*)cdata;
    cipher_descriptor[sym->idx].done(&sym->skey);
    ckfree((void *)sym);
    return;
}

static int
Tomcrypt_Cipher(ClientData cdata, Tcl_Interp *interp,
    int objc, Tcl_Obj *const objv[])
{
    Tcl_Obj *obj;
    unsigned char *key;
    int keylen;
    int rounds;
    int idx;
    int err;
    TCcipher *sym;

    if(objc < 4 || objc > 5){
        Tcl_WrongNumArgs(interp, 1, objv, "dest key ?rounds");
        return TCL_ERROR;
    }

    key = Tcl_GetByteArrayFromObj(objv[3], &keylen);
    if(objc == 5){
        if(Tcl_GetIntFromObj(interp, objv[4], &rounds) != TCL_OK){
            return TCL_ERROR;
        }
    }else{
        rounds = 0;
    }

    idx = find_cipher(Tcl_GetString(objv[2]));
    if(idx == -1){
        obj = Tcl_NewStringObj("failed to find cipher: ", -1);
        Tcl_AppendObjToObj(obj, objv[2]);
        Tcl_SetObjResult(interp, obj);
        return TCL_ERROR;
    }

    if((sym = (TCcipher*)ckalloc(sizeof(TCcipher))) == NULL){
        ERRSTR(interp, "memory allocation failed");
    }
    sym->idx = idx;
    err = cipher_descriptor[idx].setup(key, keylen, rounds, &sym->skey);
    if(err != CRYPT_OK){
        ckfree((void *)sym);
        return tomerr(interp, err);
    }

    Tcl_CreateObjCommand(interp, Tcl_GetString(objv[1]), Cipher_Ensemble,
                         sym, Cipher_Cleanup);

    Tcl_SetObjResult(interp, objv[1]);
    return TCL_OK;
}

static int
regciph(Tcl_Interp *interp,
    const char *name,
    const struct ltc_cipher_descriptor *desc)
{
    if(register_cipher(desc) == -1){
        Tcl_SetObjResult(interp,
            Tcl_ObjPrintf("failed to register %s cipher", name));
        return TCL_ERROR;
    }
    return TCL_OK;
}

int
init_symmetric(Tcl_Interp *interp)
{
#define R(C) regciph(interp, #C, & C##_desc)
    R(blowfish);
    R(xtea);
    R(rc2);
    R(rc5);
    R(rc6);
    R(saferp);
    R(aes);
    R(twofish);
    R(des);
    R(des3);
    R(cast5);
    R(noekeon);
    R(skipjack);
    R(anubis);
    R(khazad);
    R(kseed);
    R(kasumi);
#undef R

    Tcl_CreateObjCommand(interp, "tomcrypt::cipher",
                         Tomcrypt_Cipher, NULL, NULL);
    return TCL_OK;
}
