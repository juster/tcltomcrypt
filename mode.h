/* Every mode has a done function with one argument: the pointer to its
 * internal tomcrypt state structure. */
typedef int mode_done(void *);

#define MODEDESC_FIELDS \
    char *name;\
    mode_done *done;

struct ModeDesc {
    MODEDESC_FIELDS
};

#define MODESTATE_FIELDS \
	int uid;\
	Tcl_HashTable *keyStore;\
	int refCount;

typedef struct ModeState {
	MODESTATE_FIELDS
	struct ModeDesc *desc;
} ModeState;

typedef int xxx_start(int, const unsigned char*, const unsigned char*,
    int, int, void *);
typedef int xxx_crypt(const unsigned char*, const unsigned char*,
    unsigned long, void*);
typedef int xxx_getiv(unsigned char *, unsigned long *, void *);
typedef int xxx_setiv(const unsigned char *, unsigned long, void *);

typedef struct XXXModeDesc {
    MODEDESC_FIELDS
    int keySize;
    xxx_start *start;
    xxx_crypt *encrypt;
    xxx_crypt *decrypt;
    xxx_getiv *getiv;
    xxx_setiv *setiv;
} XXXModeDesc;

typedef struct XXXModeState {
    MODESTATE_FIELDS
	struct XXXModeDesc *desc;
} XXXModeState;

#undef MODEDESC_FIELDS
#undef MODESTATE_FIELDS

#warning warning spam is about void pointers, sorry!
/* this causes tons of warnings because we use void pointers */
static XXXModeDesc xxxDescriptors[] = {
#define MODE(L, U) {\
    #L, L##_done, sizeof(symmetric_##U),\
    L##_start, L##_encrypt, L##_decrypt, NULL, NULL },
#define MODEIV(L, U) {\
    #L, L##_done, sizeof(symmetric_##U),\
    L##_start, L##_encrypt, L##_decrypt, L##_getiv, L##_setiv },
#ifdef LTC_ECB_MODE
    MODE(ecb, ECB)
#endif
#ifdef LTC_CFB_MODE
    MODEIV(cfb, CFB)
#endif
#ifdef LTC_CBC_MODE
    MODEIV(cbc, CBC)
#endif
#ifdef LTC_OFB_MODE
    MODEIV(ofb, OFB)
#endif
#undef MODE
#undef MODEIV
};
