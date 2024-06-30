#ifndef SPRD_VERIFY_H
#define SPRD_VERIFY_H
 void dumpHex(const char *title, uint8_t * data, int len);
void cal_sha256(uint8_t * input, uint32_t bytes_num, uint8_t * output);
bool sprd_verify_cert(uint8_t * hash_key_precert, uint8_t * hash_data, uint8_t * certptr);
uint8_t * sprd_get_sechdr_addr(uint8_t * buf);
uint8_t * sprd_get_code_addr(uint8_t * buf);
uint8_t * sprd_get_cert_addr(uint8_t * buf);
bool sprd_verify_img(uint8_t * hash_key_precert, uint8_t * imgbuf);
void sprd_secure_check(uint8_t * data_header);
bool sprd_sbdebug_verify_cert(developer_debugcert * dev_dbgcert, primary_debugcert * prim_dbgcert, sprd_keycert * cur_keycert, uint32_t dbgcert_type);
bool sprd_sbdebug_enable(uint8_t * imgbuf);
bool getpubkeyToVerifyVbmeta(char * pbkToVerifyVbmeta, char *path_key);
bool getpubkeyfrmPEM(sprd_rsapubkey * sprdPubk, char *path_key);
bool calcSignature_pkcs1(uint8_t * hash_data, int hashLen, uint8_t * signature, char *path_key);
bool calcSignature_pss(uint8_t * hash_data, int hashLen, uint8_t * signature, char *path_key);
int HexChar2Dec(unsigned char c);
int str2Num16(const unsigned char* str);
#endif	/* !HEADER_AES_H */
