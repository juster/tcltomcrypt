#include <tcl.h>
#include <tomcrypt.h>
#include "tcltomcrypt.h"
#include "mode.h"

static Tcl_Obj *
regModeKey(void *key, ModeState *state)
{
    Tcl_HashEntry *entryPtr;
    Tcl_Obj *hnd;
    int new;
    hnd = Tcl_ObjPrintf("modekey%d", ++state->uid);
    entryPtr = Tcl_CreateHashEntry(state->keyStore, Tcl_GetString(hnd), &new);
    if(!new){
        return NULL;
    }
    Tcl_SetHashValue(entryPtr, key);
    return hnd;
}

static void *
findModeKey(Tcl_Interp *interp, Tcl_Obj *hashKey, ModeState *state,
    Tcl_HashEntry **entryDest)
{
    Tcl_HashEntry *entryPtr;
    Tcl_Obj *resultObj;
    
    if(!(entryPtr = Tcl_FindHashEntry(state->keyStore, Tcl_GetString(hashKey)))){
        Tcl_SetResult(interp, "unknown cipher mode handle", NULL);
        return NULL;
    }
    if(entryDest){
        *entryDest = entryPtr;
    }
    return (void*)Tcl_GetHashValue(entryPtr);
}

static void
deleteModeKey(Tcl_HashEntry *entryPtr, ModeState *state)
{
    void *key;
    key = (void*)Tcl_GetHashValue(entryPtr);
    state->desc->done(key);
    Tcl_Free(key);
    Tcl_DeleteHashEntry(entryPtr);
    return;
}

static int
XXXModeStart(ClientData cdata, Tcl_Interp *interp,
    int objc, Tcl_Obj *const objv[])
{
    unsigned char *key;
    unsigned char *iv;
    int rounds;
    int keyLen;
    int ivLen;
    int idx;
    int err;

    XXXModeState *state;
    void *symkey;
    Tcl_Obj *hnd;

    if(objc != 5){
        Tcl_WrongNumArgs(interp, 1, objv, "cipher iv key rounds");
        return TCL_ERROR;
    }
    /* Remember: only a cipher previously registered with register_cipher can be
     * looked up later using find_cipher.
     */
    if((idx = find_cipher(Tcl_GetString(objv[1]))) == -1){
        return tomerr(interp, idx);
    }
    iv = Tcl_GetByteArrayFromObj(objv[2], &ivLen);
    if(ivLen != cipher_descriptor[idx].block_length){
        Tcl_SetStringObj(Tcl_GetObjResult(interp),
            "iv is not the same length as the cipher block", -1);
        return TCL_ERROR;
    }
    key = Tcl_GetByteArrayFromObj(objv[3], &keyLen);
    if(Tcl_GetIntFromObj(interp, objv[4], &rounds) == TCL_ERROR){
        return TCL_ERROR;
    }

    state = (XXXModeState*)cdata;
    symkey = (void*)Tcl_Alloc(state->desc->keySize);
    err = state->desc->start(idx, iv, key, keyLen, rounds, symkey);
    if(err != CRYPT_OK){
        return tomerr(interp, err);
    }

    hnd = regModeKey(symkey, (ModeState*)state);
    if(hnd == NULL){
        Tcl_SetStringObj(Tcl_GetObjResult(interp),
            "internal error: failed to store mode key", -1);
        return TCL_ERROR;
    }
    Tcl_SetObjResult(interp, hnd);
    return TCL_OK;
}

static int
XXXModeCrypt(ClientData cdata, Tcl_Interp *interp,
    int objc, Tcl_Obj *const objv[], xxx_crypt *funcPtr)
{
    unsigned char *src, *dest;
    int srcLen;
    void *keyPtr;
    int err;
    Tcl_Obj *result;

    if(objc != 3){
        Tcl_WrongNumArgs(interp, 1, objv, "handle data");
        return TCL_ERROR;
    }

    if(!(keyPtr = findModeKey(interp, objv[1], (ModeState*)cdata, NULL))){
        return TCL_ERROR;
    }
    src = Tcl_GetByteArrayFromObj(objv[2], &srcLen);
    result = Tcl_GetObjResult(interp);
    Tcl_SetByteArrayLength(result, srcLen);
    dest = Tcl_GetByteArrayFromObj(result, NULL);
    
    if((err = funcPtr(src, dest, srcLen, keyPtr)) != CRYPT_OK){
        return tomerr(interp, err);
    }
    return TCL_OK;
}

static int
XXXModeEncrypt(ClientData cdata, Tcl_Interp *interp,
    int objc, Tcl_Obj *const objv[])
{
    return XXXModeCrypt(cdata, interp, objc, objv,
        ((XXXModeState *)cdata)->desc->encrypt);
}

static int
XXXModeDecrypt(ClientData cdata, Tcl_Interp *interp,
    int objc, Tcl_Obj *const objv[])
{
    return XXXModeCrypt(cdata, interp, objc, objv,
        ((XXXModeState *)cdata)->desc->decrypt);
}

static int
XXXModeDone(ClientData cdata, Tcl_Interp *interp,
    int objc, Tcl_Obj *const objv[])
{
    void *key;
    XXXModeState *state;
    int err;
    Tcl_Obj *resultObj;
    
    state = (XXXModeState*)cdata;
    Tcl_HashEntry *entryPtr;
    if(objc != 2){
        Tcl_WrongNumArgs(interp, 1, objv, "handle");
        return TCL_ERROR;
    }
    if(!findModeKey(interp, objv[1], (ModeState*)state, &entryPtr)){
        return TCL_ERROR;
    }
    deleteModeKey(entryPtr, (ModeState*)state);
    return TCL_OK;
}

static void
XXXModeCleanup(ClientData cdata)
{
    XXXModeState *state;
    Tcl_HashEntry *entryPtr;
    Tcl_HashSearch search;
    state = (XXXModeState*)cdata;
    if(--state->refCount > 0){
       return;
    }
    while((entryPtr = Tcl_FirstHashEntry(state->keyStore, &search))){
        deleteModeKey(entryPtr, (ModeState*)state);
    }
    Tcl_Free((char*)state);
}

static int
createXXXModes(Tcl_Interp *interp, TomcryptState *tomState)
{
    XXXModeState *mode;
    char name[128];
    int i;
    int len;
    for(i=0, len=sizeof(xxxDescriptors)/sizeof(XXXModeDesc); i<len; i++){
        mode = (XXXModeState*)Tcl_Alloc(sizeof(XXXModeState));
        mode->uid = 0;
        mode->refCount = 0;
        mode->desc = xxxDescriptors + i;
        mode->keyStore = TomcryptHashTable(tomState);

        snprintf(name, 128, "::tomcrypt::%s_start", mode->desc->name);
        Tcl_CreateObjCommand(interp, name, XXXModeStart,
            (ClientData)mode, XXXModeCleanup);
        ++mode->refCount;

        snprintf(name, 128, "::tomcrypt::%s_encrypt", mode->desc->name);
        Tcl_CreateObjCommand(interp, name, XXXModeEncrypt,
            (ClientData)mode, XXXModeCleanup);
        ++mode->refCount;
        
        snprintf(name, 128, "::tomcrypt::%s_decrypt", mode->desc->name);
        Tcl_CreateObjCommand(interp, name, XXXModeDecrypt,
            (ClientData)mode, XXXModeCleanup);
        ++mode->refCount;
        
        snprintf(name, 128, "::tomcrypt::%s_done", mode->desc->name);
        Tcl_CreateObjCommand(interp, name, XXXModeDone,
            (ClientData)mode, XXXModeCleanup);
        ++mode->refCount;
    }
    return TCL_OK;
}

int
initModes(Tcl_Interp *interp, TomcryptState *state)
{
    return createXXXModes(interp, state);
}
