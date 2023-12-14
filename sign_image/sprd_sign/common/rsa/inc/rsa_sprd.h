/*****************************************************************

*****************************************************************/
#include <string.h>
#include <stdio.h>
#define false 0
#define true 1
#ifndef bool
typedef int bool;
#endif

#define RSA_3	0x3L
#define RSA_F4	0x10001L

void invert_char(unsigned char *src, int len);

/*****************************************************************
*****************************************************************/
/*
generate RSA key pair , return modulus and private exponent
parameter:
[IN] char  * pubExp: public expoenent,should be RSA_3 or RSA_F4, to be compatible with rsa->e from openssl, the pubExp should be BIG-ENDIAN like [0~3]={0x00,0x01,0x00,0x01}
[IN] int	bitLen_N: key len 2048...
[OUT]char* mod_N: store the return modulus ,length should be bitLen_N>>3 bytes
[OUT]char* prvExp: store the return private exponent ,length should be bitLen_N>>3 bytes
return value:
true: generate success
false: generate failed
*/
int RSA_Create(unsigned char *pubExp, int bitLen_N, unsigned char *mod_N, unsigned char *prvExp);
/*
encrypt using private key, means sign
parameter:
[IN] char* prvExp:  private exponent ,length should be bitLen_N>>3 bytes
[IN] char* mod_N:  modulus ,length should be bitLen_N>>3 bytes
[IN] int bitLen_N: bit length of mod_N
[IN] char * from: clear text to be signed, MAX length is bitLen_N>>3-11 due to will be padded using pkcs1
[IN] int flen:data length of "from" buffer, MAX is  bitLen_N>>3-11
[OUT] char * to:signature, always be bitLen_N>>3 bytes length
return value:
true: sign success
false: sign failed
*/
int RSA_PrvEnc(unsigned char *prvExp, unsigned char *mod_N, int bitLen_N, unsigned char *from, int flen, unsigned char *to);
/*
decrypt using pub key, means verify
parameter:
[IN] char* pubExp:  public expoenent,should be RSA_3 or RSA_F4, to be compatible with rsa->e from openssl, the pubExp should be BIG-ENDIAN like [0~3]={0x00,0x01,0x00,0x01}
[IN] char* mod_N:  modulus ,length should be bitLen_N>>3 bytes
[IN] int bitLen_N: bit length of mod_N
[IN] char * from: signature to be verified, always be bitLen_N>>3 bytes length
[OUT] char * to:clear text after public decryption
return value:
bytes length of clear data in "to" buffer, MAX is  bitLen_N>>3-11
*/
int RSA_PubDec(unsigned char *pubExp, unsigned char *mod_N, int bitLen_N, unsigned char *from, unsigned char *to);
/*
encrypt using public key
parameter:
[IN] char* pubExp:  public expoenent,should be RSA_3 or RSA_F4, to be compatible with rsa->e from openssl, the pubExp should be BIG-ENDIAN like [0~3]={0x00,0x01,0x00,0x01}
[IN] char* mod_N:  modulus ,length should be bitLen_N>>3 bytes
[IN] int bitLen_N: bit length of mod_N
[IN] char * from: clear text to be signed, MAX length is bitLen_N>>3-11 due to will be padded using pkcs1
[IN] int flen:data length of "from" buffer, MAX is  bitLen_N>>3-11
[OUT] char * to: cipher data, always be bitLen_N>>3 bytes length
return value:
true: encrypt success
false: encrypt failed
*/
int RSA_PubEnc(unsigned char *pubExp, unsigned char *mod_N, int bitLen_N, unsigned char *from, int flen, unsigned char *to);
/*
decrypt using private key
parameter:
[IN] char* prvExp:  private exponent ,length should be bitLen_N>>3 bytes
[IN] char* mod_N:  modulus ,length should be bitLen_N>>3 bytes
[IN] int bitLen_N: bit length of mod_N
[IN] char * from: cipher data to be decrypted, always be bitLen_N>>3 bytes length
[OUT] char * to:clear text after public decryption
return value:
bytes length of clear data in "to" buffer, MAX is  bitLen_N>>3-11
*/
int RSA_PrvDec(unsigned char *prvExp, unsigned char *mod_N, int bitLen_N, unsigned char *from, unsigned char *to);
