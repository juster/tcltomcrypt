#include <tcl.h>
#include <tomcrypt.h>
#include "tcltomcrypt.h"

typedef const struct ltc_cipher_descriptor CipherDesc;
typedef (*CipherFunc)(const unsigned char *, unsigned char *, symmetric_key *);
typedef struct CipherState {
    int uid;
    Tcl_HashTable *hash;
    CipherDesc *desc;
} CipherState;

void
deleteSymKey(CipherDesc *desc, Tcl_HashEntry *entryPtr)
{
    symmetric_key *symKey;
    symKey = (symmetric_key*)Tcl_GetHashValue(entryPtr);
    Tcl_DeleteHashEntry(entryPtr);
    desc->done(symKey);
    Tcl_Free((char*)symKey);
    return;
}

static void
CipherCleanup(ClientData cdata)
{
    CipherState *state;
    Tcl_HashEntry *entryPtr;
    Tcl_HashSearch search;

    fprintf(stderr, "DBG: CipherCleanup\n");
    state = (CipherState*)cdata;
    while(entryPtr = Tcl_FirstHashEntry(state->hash, &search)){
        fprintf(stderr, "DBG: deleting symkey for %s\n", state->desc->name);
        deleteSymKey(state->desc, entryPtr);
    }
    return;
}

static int
CipherDone(ClientData cdata, Tcl_Interp *interp,
    int objc, Tcl_Obj *const objv[])
{
    CipherState *state;
    Tcl_HashEntry *entryPtr;
    int err;

    if(objc != 2){
        Tcl_WrongNumArgs(interp, 1, objv, "symkey");
        return TCL_ERROR;
    }
    state = (CipherState*)cdata;
    if((entryPtr = Tcl_FindHashEntry(state->hash, Tcl_GetString(objv[1])))){
        deleteSymKey(state->desc, entryPtr);
    }else{
        Tcl_SetStringObj(Tcl_GetObjResult(interp),
            "invalid symkey provided", -1);
        return TCL_ERROR;
    }

    return TCL_OK;
}

static int
cipheraction(CipherState *state, Tcl_Interp *interp,
    int objc, Tcl_Obj *const objv[],
    CipherFunc func)
{
    Tcl_HashEntry *entryPtr;
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

    entryPtr = Tcl_FindHashEntry(state->hash, Tcl_GetString(objv[2]));
    if(entryPtr == NULL){
        Tcl_SetStringObj(Tcl_GetObjResult(interp),
            "invalid symkey provided", -1);
        return TCL_ERROR;
    }
    skey = (symmetric_key*)Tcl_GetHashValue(entryPtr);
    if((err = func(buf, out, skey)) != CRYPT_OK){
        return tomerr(interp, err);
    }
    
    Tcl_SetByteArrayObj(result, out, bufLen);
    return TCL_OK;
}

static int
CipherECBEncrypt(ClientData cdata, Tcl_Interp *interp,
    int objc, Tcl_Obj *const objv[])
{
    CipherState *state;
    state = (CipherState*)cdata;
    return cipheraction(state, interp, objc, objv, state->desc->ecb_encrypt);
}

static int
CipherECBDecrypt(ClientData cdata, Tcl_Interp *interp,
    int objc, Tcl_Obj *const objv[])
{
    CipherState *state;
    state = (CipherState*)cdata;
    return cipheraction(state, interp, objc, objv, state->desc->ecb_decrypt);
}

static int
CipherSetup(ClientData cdata, Tcl_Interp *interp,
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
    char name[64];
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
    snprintf(name, 64, "%skey%d", state->desc->name, ++state->uid);
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
descarray(CipherDesc *desc)
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
createCipherCmds(Tcl_Interp *interp, CipherDesc *desc, Tcl_HashTable *hash)
{
    CipherState *state;
    char cmd[128];

    state = (CipherState*)Tcl_Alloc(sizeof(CipherState));
    state->uid = 0;
    state->hash = hash;
    state->desc = desc;
    snprintf(cmd, 128, "tomcrypt::%s_setup", desc->name);
    Tcl_CreateObjCommand(interp, cmd, CipherSetup,
        (ClientData)state, NULL);
    snprintf(cmd, 128, "tomcrypt::%s_ecb_encrypt", desc->name);
    Tcl_CreateObjCommand(interp, cmd, CipherECBEncrypt,
        (ClientData)state, NULL);
    snprintf(cmd, 128, "tomcrypt::%s_ecb_decrypt", desc->name);
    Tcl_CreateObjCommand(interp, cmd, CipherECBDecrypt,
        (ClientData)state, NULL);
    snprintf(cmd, 128, "tomcrypt::%s_done", desc->name);
    Tcl_CreateObjCommand(interp, cmd, CipherDone,
        (ClientData)state, CipherCleanup);
}

static int
regCipherTcl(Tcl_Interp *interp, CipherDesc *desc,
    const char *ary, TomcryptState *state)
{
    Tcl_Obj *obj;
    Tcl_HashTable *hashPtr;

    if(register_cipher(desc) == -1){
        Tcl_SetObjResult(interp,
            Tcl_ObjPrintf("failed to register %s cipher", desc->name));
        return TCL_ERROR;
    }

    if(Tcl_SetVar2Ex(interp, ary, desc->name, descarray(desc),
        TCL_LEAVE_ERR_MSG) == NULL){
        return TCL_ERROR;
    }

    hashPtr = &state->cipherHashes[state->cipherHashCount++];
    Tcl_InitHashTable(hashPtr, TCL_STRING_KEYS);
    createCipherCmds(interp, desc, hashPtr);

    return TCL_OK;
}

int
initCiphers(Tcl_Interp *interp, TomcryptState *state)
{
#define RC(C)\
    if(regCipherTcl(interp, & C##_desc, "tomcrypt::cipher", state) != TCL_OK)\
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
