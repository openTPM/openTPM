#ifndef TPM_TYPES_H
#define TPM_TYPES_H

/* wrapper header file to include the TCG definitions */

typedef uint8_t   UINT8;
typedef uint16_t  UINT16;
typedef uint32_t  UINT32;
typedef	UINT8 BYTE;

// the following defs are straight from the TCG published headers

// entity types
#define TPM_ET_KEYHANDLE               ((UINT16)0x0001)     /* 1.1b */
#define TPM_ET_OWNER                   ((UINT16)0x0002)     /* 1.1b */
#define TPM_ET_DATA                    ((UINT16)0x0003)     /* 1.1b */
#define TPM_ET_SRK                     ((UINT16)0x0004)     /* 1.1b */
#define TPM_ET_KEY                     ((UINT16)0x0005)     /* 1.1b */
#define TPM_ET_REVOKE                  ((UINT16)0x0006)
#define TPM_ET_DEL_OWNER_BLOB          ((UINT16)0x0007)
#define TPM_ET_DEL_ROW                 ((UINT16)0x0008)
#define TPM_ET_DEL_KEY_BLOB            ((UINT16)0x0009)
#define TPM_ET_COUNTER                 ((UINT16)0x000a)
#define TPM_ET_NV                      ((UINT16)0x000b)
#define TPM_ET_RESERVED_HANDLE         ((UINT16)0x0040)

// keyHandle types
#define TPM_KH_SRK                     ((UINT32)0x40000000)
#define TPM_KH_OWNER                   ((UINT32)0x40000001)
#define TPM_KH_REVOKE                  ((UINT32)0x40000002)
#define TPM_KH_TRANSPORT               ((UINT32)0x40000003)
#define TPM_KH_OPERATOR                ((UINT32)0x40000004)
#define TPM_KH_ADMIN                   ((UINT32)0x40000005)
#define TPM_KH_EK                      ((UINT32)0x40000006)

//-------------------------------------------------------------------
// Part 2, section 5.8: Key usage values

typedef UINT16 TPM_KEY_USAGE;                               /* 1.1b */
#define TPM_KEY_SIGNING                ((UINT16)0x0010)     /* 1.1b */
#define TPM_KEY_STORAGE                ((UINT16)0x0011)     /* 1.1b */
#define TPM_KEY_IDENTITY               ((UINT16)0x0012)     /* 1.1b */
#define TPM_KEY_AUTHCHANGE             ((UINT16)0x0013)     /* 1.1b */
#define TPM_KEY_BIND                   ((UINT16)0x0014)     /* 1.1b */
#define TPM_KEY_LEGACY                 ((UINT16)0x0015)     /* 1.1b */
#define TPM_KEY_MIGRATE                ((UINT16)0x0016)

typedef UINT16 TPM_SIG_SCHEME;                              /* 1.1b */
#define TPM_SS_NONE                    ((UINT16)0x0001)     /* 1.1b */
#define TPM_SS_RSASSAPKCS1v15_SHA1     ((UINT16)0x0002)     /* 1.1b */
#define TPM_SS_RSASSAPKCS1v15_DER      ((UINT16)0x0003)     /* 1.1b */
#define TPM_SS_RSASSAPKCS1v15_INFO     ((UINT16)0x0004)

typedef UINT16 TPM_ENC_SCHEME;                              /* 1.1b */
#define TPM_ES_NONE                    ((UINT16)0x0001)     /* 1.1b */
#define TPM_ES_RSAESPKCSv15            ((UINT16)0x0002)     /* 1.1b */
#define TPM_ES_RSAESOAEP_SHA1_MGF1     ((UINT16)0x0003)     /* 1.1b */
#define TPM_ES_SYM_CNT                 ((UINT16)0x0004)
#define TPM_ES_SYM_OFB                 ((UINT16)0x0005)
#define TPM_ES_SYM_CBC_PKCS5PAD        ((UINT16)0x00ff)

//-------------------------------------------------------------------
// Part 2, section 5.9: TPM_AUTH_DATA_USAGE values

typedef BYTE TPM_AUTH_DATA_USAGE;                           /* 1.1b */
#define TPM_AUTH_NEVER                 ((BYTE)0x00)         /* 1.1b */
#define TPM_AUTH_ALWAYS                ((BYTE)0x01)         /* 1.1b */
#define TPM_AUTH_PRIV_USE_ONLY         ((BYTE)0x11)


//-------------------------------------------------------------------
// Part 2, section 5.10: TPM_KEY_FLAGS flags

typedef UINT32 TPM_KEY_FLAGS;                               /* 1.1b */
#define TPM_REDIRECTION                ((UINT32)0x00000001) /* 1.1b */
#define TPM_MIGRATABLE                 ((UINT32)0x00000002) /* 1.1b */
#define TPM_VOLATILE                   ((UINT32)0x00000004) /* 1.1b */
#define TPM_PCRIGNOREDONREAD           ((UINT32)0x00000008)
#define TPM_MIGRATEAUTHORITY           ((UINT32)0x00000010)

// addes this def to TCG standard header
#define TPM_NONMIGRATABLE              ((UINT32)0x00000000) /* 1.1b */


#endif

