#include <tcl.h>
#include <tomcrypt.h>
#include "tcltomcrypt.h"

typedef const struct ltc_cipher_descriptor ciphdesc;
typedef (*cipherfunc)(const unsigned char *, unsigned char *, symmetric_key *);
typedef struct CipherState {
    int uid;
    Tcl_HashTable *hash;
    ciphdesc *desc;
} CipherState;

static symmetric_key *
lookupSymKey(Tcl_HashTable *hash, Tcl_Obj *symkey)
{
    Tcl_HashEntry *entry;
    entry = Tcl_FindHashEntry(hash, Tcl_GetString(symkey));
    if(entry == NULL){
        return NULL;
    }
    return (symmetric_key *)Tcl_GetHashValue(entry);
}

static int
cipheraction(CipherState *state, Tcl_Interp *interp,
    int objc, Tcl_Obj *const objv[],
    cipherfunc func)
{
    symmetric_key *skey;

    Tcl_Obj *bufObj;
    unsigned char *buf;
    int bufLen;
    unsigned char out[MAXBLOCKSIZE];
    Tcl_Obj *result;
    int err;

    if(objc != 3){
        Tcl_WrongNumArgs(interp, 1, objv, "bytes symkey");
        return TCL_ERROR;
    }
    result = Tcl_GetObjResult(interp);

    buf = Tcl_GetByteArrayFromObj(objv[1], &bufLen);
    if(bufLen < state->desc->block_length){
        Tcl_SetStringObj(result, "bytes are shorter than cipher block length", -1);
        return TCL_ERROR;
    }else if(bufLen > state->desc->block_length){
        Tcl_SetStringObj(result, "bytes are longer than cipher block length", -1);
        return TCL_ERROR;
    }
    skey = lookupSymKey(state->hash, objv[2]);
    if(skey == NULL){
        Tcl_SetStringObj(result, "invalid symkey handle provided", -1);
        return TCL_ERROR;
    }
    if((err = func(buf, out, skey)) != CRYPT_OK){
        return tomerr(interp, err);
    }
    
    Tcl_SetByteArrayObj(result, out, bufLen);
    return TCL_OK;
}

static int
Tomcrypt_CipherECBEncrypt(ClientData cdata, Tcl_Interp *interp,
    int objc, Tcl_Obj *const objv[])
{
    CipherState *state;
    state = (CipherState*)cdata;
    return cipheraction(state, interp, objc, objv, state->desc->ecb_encrypt);
}

static int
Tomcrypt_CipherECBDecrypt(ClientData cdata, Tcl_Interp *interp,
    int objc, Tcl_Obj *const objv[])
{
    CipherState *state;
    state = (CipherState*)cdata;
    return cipheraction(state, interp, objc, objv, state->desc->ecb_decrypt);
}

static int
Tomcrypt_CipherSetup(ClientData cdata, Tcl_Interp *interp,
    int objc, Tcl_Obj *const objv[])
{
    symmetric_key *symkey;
    unsigned char *keyraw;
    int keylen;
    int rounds;
    int err;

    CipherState *state;
    Tcl_HashEntry *entry;
    Tcl_Obj *result;
    char name[32];
    int new;

    if(objc < 2 || objc > 3){
        Tcl_WrongNumArgs(interp, 1, objv, "key ?rounds");
        return TCL_ERROR;
    }

    if(objc < 3){
        rounds = 0;
    }else if(Tcl_GetIntFromObj(interp, objv[2], &rounds) == TCL_ERROR){
        return TCL_ERROR;
    }

    keyraw = Tcl_GetByteArrayFromObj(objv[1], &keylen);
    state = (CipherState*)cdata;
    symkey = (symmetric_key*)Tcl_Alloc(sizeof(symmetric_key));
    if((err = state->desc->setup(keyraw, keylen, rounds, symkey)) != CRYPT_OK){
        Tcl_Free((char*)symkey);
        return tomerr(interp, err);
    }

    /* Store the tomcrypt symmetric_key inside our internal state. */
    snprintf(name, 32, "symkey%d", ++state->uid);
    result = Tcl_GetObjResult(interp);
    Tcl_SetStringObj(result, name, -1);
    entry = Tcl_CreateHashEntry(state->hash, name, &new);
    if(!new){
        Tcl_Free((char*)symkey);
        Tcl_SetStringObj(result, "internal error: duplicate key name", -1);
        return TCL_ERROR;
    }
    Tcl_SetHashValue(entry, (ClientData)symkey);

    return TCL_OK;
}

static Tcl_Obj*
descarray(ciphdesc *desc)
{
    Tcl_Obj *clist[12];
    int i;

    i = 0;
#define STR(X) clist[i++] = Tcl_NewStringObj(X, -1)
#define INT(X) clist[i++] = Tcl_NewIntObj(X)
    STR("name");
    STR(desc->name);
    STR("ID");
    INT(desc->ID);    
    STR("min_key_length");
    INT(desc->min_key_length);
    STR("man_key_length");
    INT(desc->max_key_length);
    STR("block_length");
    INT(desc->block_length);
    STR("default_rounds");
    INT(desc->default_rounds);
#undef STR
#undef INT

    return Tcl_NewListObj(12, clist);
}

static void
newciphercmds(Tcl_Interp *interp, ciphdesc *desc, Tcl_HashTable *hash)
{
    CipherState *state;
    char cmd[128];

    state = (CipherState*)Tcl_Alloc(sizeof(CipherState));
    state->uid = 0;
    state->hash = hash;
    state->desc = desc;
    snprintf(cmd, 128, "tomcrypt::%s_setup", desc->name);
    Tcl_CreateObjCommand(interp, cmd, Tomcrypt_CipherSetup,
        (ClientData)state, NULL);
    snprintf(cmd, 128, "tomcrypt::%s_ecb_encrypt", desc->name);
    Tcl_CreateObjCommand(interp, cmd, Tomcrypt_CipherECBEncrypt,
        (ClientData)state, NULL);
    snprintf(cmd, 128, "tomcrypt::%s_ecb_decrypt", desc->name);
    Tcl_CreateObjCommand(interp, cmd, Tomcrypt_CipherECBDecrypt,
        (ClientData)state, NULL);
/*     snprintf(cmd, 128, "tomcrypt::%s_done", desc->name); */
/*     Tcl_CreateObjCommand(interp, cmd, Tomcrypt_CipherDone, desc, NULL); */
}

static int
regciph(Tcl_Interp *interp, ciphdesc *desc,
    const char *ary, Tcl_HashTable *hash)
{
    Tcl_Obj *obj;

    if(register_cipher(desc) == -1){
        Tcl_SetObjResult(interp,
            Tcl_ObjPrintf("failed to register %s cipher", desc->name));
        return TCL_ERROR;
    }

    if(Tcl_SetVar2Ex(interp, ary, desc->name, descarray(desc),
        TCL_LEAVE_ERR_MSG) == NULL){
        return TCL_ERROR;
    }
    newciphercmds(interp, desc, hash);

    return TCL_OK;
}

int
init_symmetric(Tcl_Interp *interp, Tcl_HashTable *hash)
{
#define RC(C)\
    if(regciph(interp, & C##_desc, "tomcrypt::cipher", hash) != TCL_OK)\
        return TCL_ERROR;
    RC(blowfish);
    RC(xtea);
    RC(rc2);
    RC(rc5);
    RC(rc6);
    RC(saferp);
    RC(aes);
    RC(twofish);
    RC(des);
    RC(des3);
    RC(cast5);
    RC(noekeon);
    RC(skipjack);
    RC(anubis);
    RC(khazad);
    RC(kseed);
    RC(kasumi);
#undef RC

    return TCL_OK;
}

void
cleanup_symmetric(Tcl_HashTable *hash)
{
    /* TODO: free symmetric keys in symHash hash table */
}
