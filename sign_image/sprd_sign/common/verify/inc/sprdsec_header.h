
#ifndef __SPRDSEC_HEADER_H
#define __SPRDSEC_HEADER_H

#ifndef _GCC_WRAP_STDINT_H
#include <stdint.h>
#endif

#define MAGIC_SIZE 8
#define VERSION_EBL 0
#define VERSION_NBL 1
#define CERTTYPE_CONTENT 0
#define CERTTYPE_KEY 1
#define CERTTYPE_PRIMDBG 2
#define CERTTYPE_DEVELOPDBG 3

#define DWORD unsigned long
#define  SPRD_RSAPUBKLEN  sizeof(sprd_rsapubkey)
//#define  VBMETA_USE_2048 0 //set in makefile
#define  SPRD_RSA2048PUBKLEN  (520)
#define  SPRD_RSA4096PUBKLEN  (1032)
#pragma pack(1)

typedef struct{
    uint32_t  mMagicNum;        // "BTHD"=="0x42544844"=="boothead"
    uint32_t  mVersion;         // 1
    uint8_t   mPayloadHash[32]; // sha256 hash value
    uint64_t  mImgAddr;         // image loaded address
    uint32_t  mImgSize;         // image size
    uint32_t  is_packed;        // packed image flag 0:false 1:true
    uint32_t  mFirmwareSize;    // runtime firmware size
    uint8_t   reserved[452];    // 452 + 15*4 = 512
} sys_img_header;

#pragma pack()
#define RSA_KEY_BITS_LEN_MAX 2048
#define RSA_KEY_BYTE_LEN_MAX (RSA_KEY_BITS_LEN_MAX>>3)
#define HASH_BYTE_LEN	 32
#define KEYCERT_HASH_LEN 72
#define CNTCERT_HASH_LEN 40
#ifdef DEBUGMASK_32
#define PRIMDBG_HASH_LEN 40 //primary_cert->hash...mask...resverd
#define DEVEDBG_HASH_LEN 36 //developer_cert->debug_mask...socid
#else
#define PRIMDBG_HASH_LEN 44 //primary_cert->hash...mask...resverd
#define DEVEDBG_HASH_LEN 40 //developer_cert->debug_mask...socid
#endif
#pragma pack(1)
typedef struct sprdsignedimageheader {

	/* Magic number */
	uint8_t magic[MAGIC_SIZE];
	/* Version of this header format */
	uint32_t header_version_major;
	/* Version of this header format */
	uint32_t header_version_minor;

	/*image body, plain or cipher text */
	uint64_t payload_size;
	uint64_t payload_offset;

	/*offset from itself start */
	/*content certification size,if 0,ignore */
	uint64_t cert_size;
	uint64_t cert_offset;

	/*(opt)private content size,if 0,ignore */
	uint64_t priv_size;
	uint64_t priv_offset;

	/*(opt)debug/rma certification primary size,if 0,ignore */
	uint64_t cert_dbg_prim_size;
	uint64_t cert_dbg_prim_offset;

	/*(opt)debug/rma certification second size,if 0,ignore */
	uint64_t cert_dbg_developer_size;
	uint64_t cert_dbg_developer_offset;

} sprdsignedimageheader;

typedef struct sprd_rsapubkey {
	uint32_t keybit_len;	//1024/2048,max 2048
	uint32_t e;
	uint8_t mod[RSA_KEY_BYTE_LEN_MAX];
} sprd_rsapubkey;



typedef struct sprd_keycert {
	uint32_t certtype;	//1:key cert
	sprd_rsapubkey pubkey;	//pubkey for this cert, to verify signature in this cert
	uint8_t hash_data[HASH_BYTE_LEN];	//hash of current image data
	uint8_t hash_key[HASH_BYTE_LEN];	// hash of pubkey in next cert
	uint32_t type;
	uint32_t version;
	uint8_t signature[RSA_KEY_BYTE_LEN_MAX];	//signature of hash_data+hash_key
} sprd_keycert;

typedef struct sprd_contentcert {
	uint32_t certtype;	//0:content cert
	sprd_rsapubkey pubkey;	//pubkey for this cert, to verify signature in this cert
	uint8_t hash_data[HASH_BYTE_LEN];	//hash of image component
	uint32_t type;
	uint32_t version;
	uint8_t signature[RSA_KEY_BYTE_LEN_MAX];	//signature of hash_data
} sprd_contentcert;

typedef struct primary_debugcert {
	uint32_t cert_type;	//debug cert
	sprd_rsapubkey pubkey;	//pubkey for verify this signature

	uint8_t devkey_debug_hash_data[HASH_BYTE_LEN];	//hash of dev_pubkey
	#ifdef DEBUGMASK_32
	uint32_t debug_mask;
	#else
	uint64_t debug_mask;
	#endif
	uint32_t reserved;

	uint8_t devkey_debug_signature[RSA_KEY_BYTE_LEN_MAX];	//signature of  debug_mask & reserved + hash of dev_pubkey

} primary_debugcert;

typedef struct developer_debugcert {
	uint32_t cert_type;	//debug cert

	sprd_rsapubkey dev_pubkey;	//developer pubkey
	#ifdef DEBUGMASK_32
	uint32_t debug_mask;
	#else
	uint64_t debug_mask;
	#endif
    uint8_t soc_id[HASH_BYTE_LEN];
	uint8_t dev_signature[RSA_KEY_BYTE_LEN_MAX];	//signature hash of uid0~uid1+debug_mask
} developer_debugcert;
#pragma pack()
#endif
