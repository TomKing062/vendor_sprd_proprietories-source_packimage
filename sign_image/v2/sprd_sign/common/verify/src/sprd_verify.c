
#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "openssl/err.h"
#include "openssl/bn.h"

#include "rsa_sprd.h"
#include "sprdsec_header.h"
#include "sec_string.h"
#include "sprdsha.h"
#include <malloc.h>

#define SEC_DEBUG

#ifdef SEC_DEBUG
#define secf(fmt, args...) do { printf("%s(): ", __func__); printf(fmt, ##args); } while (0)
#else
#define secf(fmt, args...)
#endif

typedef enum
{
	SECBOOT_VERIFY_SUCCESS = 0,
	SECBOOT_VERIFY_FAIL = 1,
	SECBOOT_SET_SWVERSION_FAIL
}SecBoot_Result_Ret;

 int HexChar2Dec(unsigned char c)
{
    if ( '0'<=c && c<='9' ) {
            return (unsigned int)(c-'0');
        } else if ( 'a'<=c && c<='f' ) {
                return ( (unsigned int)(c-'a') + 10 );
            } else if ( 'A'<=c && c<='F' ) {
                    return ( (unsigned int)(c-'A') + 10 );
                } else {
                        return -1;
                    }
}

int str2Num16(const unsigned char* str)
{
  return (str[1] == '\0') ? HexChar2Dec(str[0]) : HexChar2Dec(str[0])*16+HexChar2Dec(str[1]);
}

void dumpHex(const char *title, uint8_t * data, int len)
{
	int i, j;
	int N = len / 16 + 1;
	printf("%s\n", title);
	printf("dumpHex:%d bytes", len);
	for (i = 0; i < N; i++) {
		printf("\r\n");
		for (j = 0; j < 16; j++) {
			if (i * 16 + j >= len)
				goto end;
			printf("%02x", data[i * 16 + j]);
		}
	}
end:	printf("\r\n");
	return;
}

void cal_sha256(uint8_t * input, uint32_t bytes_num, uint8_t * output)
{
	if ((NULL != input) && (NULL != output)) {
		sha256_csum_wd(input, bytes_num, output, 0);
	} else {
		secf("\r\tthe pointer is error,pls check it\n");
	}
}

bool sprd_verify_cert(uint8_t * hash_key_precert, uint8_t * hash_data, uint8_t * certptr)
{
	bool ret = false;

	uint8_t certtype = *certptr;

	if ((certtype == CERTTYPE_CONTENT) || (certtype == CERTTYPE_KEY)) {

		if (certtype == CERTTYPE_KEY) {

			sprd_keycert *curcertptr = (sprd_keycert *) certptr;
			uint8_t temphash_data[HASH_BYTE_LEN];
			cal_sha256((uint8_t *) & (curcertptr->pubkey), SPRD_RSAPUBKLEN, temphash_data);

			if (sec_memcmp(hash_data, curcertptr->hash_data, HASH_BYTE_LEN)
			    //||memcmp(hash_key_precert,temphash_data,HASH_BYTE_LEN)
			    ) {
				printf("cmp diffent\r\n");
				return false;
			}

			uint8_t *to = (uint8_t *) malloc((curcertptr->pubkey.keybit_len) >> 3);

			int ret = RSA_PubDec((uint8_t *) & (curcertptr->pubkey.e),
					     curcertptr->pubkey.mod, curcertptr->pubkey.keybit_len,
					     curcertptr->signature, to);

			if (!sec_memcmp(curcertptr->hash_data, to, KEYCERT_HASH_LEN)) {
				secf("\nRSA verify Success\n");
                free(to);
				return true;
			} else {
				secf("\nRSA verify err\n");
                free(to);
				return false;
			}

		}

		else {		//certtype is content

			sprd_contentcert *curcertptr = (sprd_contentcert *) certptr;
			uint8_t temphash_data[HASH_BYTE_LEN];

			cal_sha256((uint8_t *) & (curcertptr->pubkey), SPRD_RSAPUBKLEN, temphash_data);

			if (sec_memcmp(hash_data, curcertptr->hash_data, HASH_BYTE_LEN)
			    || sec_memcmp(hash_key_precert, temphash_data, HASH_BYTE_LEN)
			    ) {
				printf("cmp diffent\r\n");
				return false;
			}

			uint8_t *to = (uint8_t *) malloc((curcertptr->pubkey.keybit_len) >> 3);

			int ret = RSA_PubDec((uint8_t *) & (curcertptr->pubkey.e),
					     curcertptr->pubkey.mod, curcertptr->pubkey.keybit_len,
					     curcertptr->signature, to);
			if(ret <= 0)
			{
			        secf("\nRSA_PubDec() return error !!!\n");
                                free(to);
				return false;
			}
#if 1
			if (!sec_memcmp(curcertptr->hash_data, to, ret)) {
				secf("\nRSA verify Success\n");
                free(to);
				return true;
			} else {
				secf("\nRSA verify Failed\n");
                free(to);
				return false;
			}
#endif
		}

	} else {
		secf("invalid cert type %d!!", certtype);
		ret = false;
	}

	return ret;
}

/*
uint8_t *hash_key_precert: hash of of pub key in pre cert or OTP, used to verify the pub key in current image
uint8_t *imgbuf: current image need to verify
*/

uint8_t *sprd_get_sechdr_addr(uint8_t * buf)
{
	if (NULL == buf) {
		secf("\r\t input of get_sechdr_Addr err\n");
		return (uint8_t *)SECBOOT_VERIFY_FAIL;
	}
	sys_img_header *imghdr = (sys_img_header *) buf;
	uint8_t *sechdr = buf + imghdr->mImgSize + sizeof(sys_img_header);
	return sechdr;
}

uint8_t *sprd_get_code_addr(uint8_t * buf)
{
	sprdsignedimageheader *sechdr_addr = (sprdsignedimageheader *) sprd_get_sechdr_addr(buf);
	uint8_t *code_addr = buf + sechdr_addr->payload_offset;
	return code_addr;
}

uint8_t *sprd_get_cert_addr(uint8_t * buf)
{
	sprdsignedimageheader *sechdr_addr = (sprdsignedimageheader *) sprd_get_sechdr_addr(buf);
	uint8_t *cert_addr = buf + sechdr_addr->cert_offset;
	return cert_addr;
}

bool sprd_verify_img(uint8_t * hash_key_precert, uint8_t * imgbuf)
{
	sprdsignedimageheader *imghdr = (sprdsignedimageheader *) sprd_get_sechdr_addr(imgbuf);
	uint8_t *code_addr = sprd_get_code_addr(imgbuf);
	uint8_t soft_hash_data[HASH_BYTE_LEN];

	cal_sha256(code_addr, imghdr->payload_size, soft_hash_data);
	uint8_t *curcertptr = sprd_get_cert_addr(imgbuf);

	bool result = sprd_verify_cert(hash_key_precert, (uint8_t *) soft_hash_data, curcertptr);

	return result;
}

void sprd_secure_check(uint8_t * data_header)
{

	/*get current image's hash key & verify the downloading img */
	uint8_t *hash_key_next = NULL;
	sprd_keycert *certtype = (sprd_keycert *) sprd_get_cert_addr(data_header);
	if (CERTTYPE_KEY == certtype->certtype)
		hash_key_next = certtype->hash_key;

	else{
		hash_key_next = NULL;
		secf("\r\t hash_key_next = NULL !!!\n");
		while (1) ;
	}
	if (false == sprd_verify_img(hash_key_next, data_header)) {
		secf("\r\t sprd_secure_check err\n");
		while (1) ;
	}
}

bool sprd_sbdebug_verify_cert(developer_debugcert * dev_dbgcert, primary_debugcert * prim_dbgcert, sprd_keycert * cur_keycert, uint32_t dbgcert_type)
{
	uint8_t temphash_data[HASH_BYTE_LEN];

	int ret;

	uint8_t *to;

	if (CERTTYPE_PRIMDBG == dbgcert_type) {
		/*1  cal key hash */
		cal_sha256((uint8_t *) & (prim_dbgcert->pubkey), SPRD_RSAPUBKLEN, temphash_data);	//cal primary pubkey hash & compare with its hash in keycert

		if (!sec_memcmp(cur_keycert->hash_key, temphash_data, HASH_BYTE_LEN)) {
			secf("\nprimary key verify Success\n");
		} else {
			secf("\nprimary key verify Failed\n");
			return false;
		}

		to = (uint8_t *) malloc((cur_keycert->pubkey.keybit_len) >> 3);
		/*2 decrypty  */
		ret = RSA_PubDec((uint8_t *) & (prim_dbgcert->pubkey.e), prim_dbgcert->pubkey.mod, prim_dbgcert->pubkey.keybit_len, prim_dbgcert->devkey_debug_signature, to);	/*verify primary cert */

		if ((!sec_memcmp(prim_dbgcert->devkey_debug_hash_data, to, PRIMDBG_HASH_LEN))) {
			secf("\nprimary cert  verify Success\n");
			free(to);
			return true;
		} else {
			secf("\nprimary cert verify Failed\n");
			free(to);
			return false;
		}

	} else if (CERTTYPE_DEVELOPDBG == dbgcert_type) {	/* verify developer dbg cert */
		/*1 cal key hash */
		cal_sha256((uint8_t *) (&dev_dbgcert->dev_pubkey), SPRD_RSAPUBKLEN, temphash_data);

		if ((!sec_memcmp(prim_dbgcert->devkey_debug_hash_data, temphash_data, HASH_BYTE_LEN))) {
			secf("\nprimary key verify Success\n");
		} else {
			secf("\nprimary key verify Failed\n");
			return false;
		}

		to = (uint8_t *) malloc((cur_keycert->pubkey.keybit_len) >> 3);

		/*2 decripty signature */

		ret = RSA_PubDec((uint8_t *) & (dev_dbgcert->dev_pubkey.e),
				 dev_dbgcert->dev_pubkey.mod, dev_dbgcert->dev_pubkey.keybit_len, dev_dbgcert->dev_signature, to);

		if ((!sec_memcmp(&dev_dbgcert->debug_mask, to, DEVEDBG_HASH_LEN))) {
			secf("\ndeveloper cert verify Success\n");
			free(to);
			return true;
		} else {
			secf("\ndeveloper cert verify Failed\n");
			free(to);
			return false;
		}

	}

	return false;
}

bool sprd_sbdebug_enable(uint8_t * imgbuf)
{				/*imgbuf is the addr of signed img loaded in iram */
	int ret = 0;
	uint32_t uid0, uid1;
    uint8_t socid[32];
	uint32_t mask;
	bool flag;
	sys_img_header *ebl = (sys_img_header *) (imgbuf);
	sprdsignedimageheader *imghdr = (sprdsignedimageheader *) (imgbuf + ebl->mImgSize + sizeof(sys_img_header));

	developer_debugcert *devptr = (developer_debugcert *) (imgbuf + imghdr->cert_dbg_developer_offset);
	primary_debugcert *primptr = (primary_debugcert *) (imgbuf + imghdr->cert_dbg_prim_offset);
	sprd_keycert *keycertptr = (sprd_keycert *) (imgbuf + imghdr->cert_offset);

	if (0 == imghdr->cert_dbg_prim_size)	/*if primary size is 0 ,ignore */
		return false;

	/*verify pricert */
	flag = sprd_sbdebug_verify_cert(devptr, primptr, keycertptr, CERTTYPE_PRIMDBG);
	if (true == flag) {

		flag = sprd_sbdebug_verify_cert(devptr, primptr, keycertptr, CERTTYPE_DEVELOPDBG);
	}

	if (false == flag) {
		/*disable dbg */

		return false;
	}

	/*get uid & mask */
	/*
	   uid0 is efuse block0   uid1 is efuse block1,if there is no efuse,don't check uid, only set dbg mask
	 */
    memcpy(socid,devptr->soc_id,32);
	mask = devptr->debug_mask & primptr->debug_mask;

	//secf("uid0: %x , uid1: %x  mask: %x\n", uid0, uid1, mask);

	/*compare uid & set dbg mask */
	/* pls add enable dbg code */
	return true;

}

bool getpubkeyToVerifyVbmeta(char * pbkToVerifyVbmeta, char *path_key)
{
	char *p_en;
	RSA *p_rsa;
	FILE *file;
	int flen, rsa_len;
	size_t ret_num;

	if ((file = fopen(path_key, "rb")) == NULL) {
		perror("open key file error");
		return false;
	}
#if VBMETA_USE_2048
	ret_num = fread((void *)pbkToVerifyVbmeta, 1, SPRD_RSA2048PUBKLEN, file);
#else
	ret_num = fread((void *)pbkToVerifyVbmeta, 1, SPRD_RSA4096PUBKLEN, file);
#endif
	fclose(file);
	return true;
}

bool getpubkeyfrmPEM(sprd_rsapubkey * sprdPubk, char *path_key)
{
	char *p_en;
	RSA *p_rsa;
	FILE *file;
	int flen, rsa_len;
	if ((file = fopen(path_key, "rb")) == NULL) {
		perror("open key file error");
		return false;
	}
	if ((p_rsa = PEM_read_RSA_PUBKEY(file, NULL, NULL, NULL)) == NULL) {
		//if((p_rsa=PEM_read_RSAPublicKey(file,NULL,NULL,NULL))==NULL){   换成这句死活通不过，无论是否将公钥分离源文件
		ERR_print_errors_fp(stdout);
		//secf("read rsa pubkey err\n");
		return false;
	}

	rsa_len = RSA_size(p_rsa);

	sprdPubk->keybit_len = rsa_len << 3;
	//BN_bn2bin(p_rsa->e,(unsigned char *)&(sprdPubk->e));
	//
	int e_size = BN_num_bytes(RSA_get0_e(p_rsa));
	BN_bn2bin(RSA_get0_e(p_rsa), ((unsigned char *)&(sprdPubk->e) + 4 - e_size));
	while (e_size < 4) {
		*((unsigned char *)&(sprdPubk->e) + 4 - e_size - 1) = 0;
		e_size++;
	}
	//

	BN_bn2bin(RSA_get0_n(p_rsa), sprdPubk->mod);

	RSA_free(p_rsa);
	fclose(file);
	return true;
}

bool calcSignature_pkcs1(uint8_t * hash_data, int hashLen, uint8_t * signature, char *path_key)
{
	RSA *p_rsa;
	FILE *file;
	if ((file = fopen(path_key, "rb")) == NULL) {
		perror("open key file error");
		return false;
	}
	if ((p_rsa = PEM_read_RSAPrivateKey(file, NULL, NULL, NULL)) == NULL) {
		ERR_print_errors_fp(stdout);
		return false;
	}
	RSA_private_encrypt(hashLen, hash_data, signature, p_rsa, RSA_PKCS1_PADDING);

	RSA_free(p_rsa);
	fclose(file);
	return true;
}

#define EM_LEN_MAX 512
#define SALT_LEN_DEFAULT 32
#define PSS_HASH_DEFAULT EVP_sha256()
#define MGF1_HASH_DEFAULT EVP_sha256()
bool calcSignature_pss(uint8_t * hash_data, int hashLen, uint8_t * signature, char *path_key)
{
         uint8_t em[EM_LEN_MAX];
         uint32_t em_len = 0;
         RSA *p_rsa;
         FILE *file;
         if ((file = fopen(path_key, "rb")) == NULL) {
                   perror("open key file error");
                   return false;
         }
         if ((p_rsa = PEM_read_RSAPrivateKey(file, NULL, NULL, NULL)) == NULL) {
                   ERR_print_errors_fp(stdout);
                   return false;
         }
         em_len = RSA_size(p_rsa);
         memset(em, 0, EM_LEN_MAX);
         RSA_padding_add_PKCS1_PSS_mgf1(p_rsa, em, hash_data, PSS_HASH_DEFAULT, MGF1_HASH_DEFAULT, SALT_LEN_DEFAULT);
		//dumpHex("hash_data", hash_data, hashLen);
		//dumpHex("padded msg:", em, em_len);
         RSA_private_encrypt(em_len, em, signature, p_rsa, RSA_NO_PADDING);
		 //dumpHex("signature after padding:", signature, em_len);
 
         RSA_free(p_rsa);
         fclose(file);
         return true;
}

