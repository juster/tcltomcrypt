#include <tcl.h>
#include <tomcrypt.h>
#include "tcltomcrypt.h"

typedef struct ModeState {
    int uid;
    Tcl_HashTable *keyStore;
    int refCount;
} ModeState;

typedef int xxx_start(int, const unsigned char*, const unsigned char*,
    int, int, void *);

typedef int mode_done(void *);

typedef struct XXXModeDesc {
    char *name;
    int keySize;
    xxx_start *start;
    mode_done *done;
} XXXModeDesc;

typedef struct XXXModeState {
    int uid;
    Tcl_HashTable *keyStore;
    int refCount;
    struct XXXModeDesc *desc;
} XXXModeState;

/* this causes tons of warnings because we use void pointers */
static XXXModeDesc xxxDescriptors[] = {
#ifdef LTC_CBC_MODE
    { "cbc", sizeof(symmetric_CBC), cbc_start, cbc_done }
#endif
};

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
findModeKey(Tcl_Obj *hndObj, ModeState *state)
{
    Tcl_HashEntry *entryPtr;
    if(!(entryPtr = Tcl_FindHashEntry(state->keyStore, Tcl_GetString(hndObj)))){
        return NULL;
    }
    return (void*)Tcl_GetHashValue(entryPtr);
}

static void
deleteModeKey(Tcl_HashEntry *entryPtr, mode_done *doneFunc)
{
    void *key;
    key = (void*)Tcl_GetHashValue(entryPtr);
    doneFunc(key);
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
        deleteModeKey(entryPtr, state->desc->done);
    }
    Tcl_Free((char*)state);
}

static int
createXXXModes(Tcl_Interp *interp, TomcryptState *tomState)
{
    XXXModeState *mode;
    char name[128];
    int i;
    for(i=0; i<(sizeof(xxxDescriptors)/sizeof(XXXModeDesc)); i++){
        mode = (XXXModeState*)Tcl_Alloc(sizeof(XXXModeState));
        mode->uid = 0;
        mode->refCount = 0;
        mode->desc = xxxDescriptors + i;
        mode->keyStore = TomcryptHashTable(tomState);

        snprintf(name, 128, "::tomcrypt::%s_start", mode->desc->name);
        Tcl_CreateObjCommand(interp, name, XXXModeStart,
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
