
#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "openssl/err.h"

#include "sprdsec_header.h"
#include "pk1.h"
#include "rsa_sprd.h"
#include "sprdsha.h"
#include "sprd_verify.h"
#include "sec_string.h"

#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdlib.h>
#include <string.h>

char* my_strsep(char** stringp, const char* delim) {
    char* start = *stringp;
    char* p;
    p = (start != NULL) ? strpbrk(start, delim) : NULL;
    if (p == NULL) {
        *stringp = NULL;
    } else {
        *p = '\0';
        *stringp = p + 1;
    }
    return start;
}

static unsigned char padding[512] = { 0 };

#define NAME_MAX_LEN 2048
//used to parse new packed modem image(modem bin+symbol)
#define MODEM_MAGIC           "SCI1"
#define MODEM_HDR_SIZE        12  // size of a block
#define SCI_TYPE_MODEM_BIN    1
#define SCI_TYPE_PARSING_LIB  2
#define MODEM_LAST_HDR        0x100
#define MODEM_SHA1_HDR        0x400
#define MODEM_SHA1_SIZE       20

#define Trusted_Firmware 1
#define Non_Trusted_Firmware 0

#define IMG_BAK_HEADER    0x42544844

typedef struct {
	unsigned int type_flags;
	unsigned int offset;
	unsigned int length;
} data_block_header_t;
//end modem parse vars

#define TRUSTED_VERSION     "trusted_version="
#define TRUSTED_VERSION_MAX 32
uint32_t  s_tver_arr[TRUSTED_VERSION_MAX + 1] =
                           {0,
                            0x1,        0x3,        0x7,        0xf,
                            0x1f,       0x3f,       0x7f,       0xff,
                            0x1ff,      0x3ff,      0x7ff,      0xfff,
                            0x1fff,     0x3fff,     0x7fff,     0xffff,
                            0x1ffff,    0x3ffff,    0x7ffff,    0xfffff,
                            0x1fffff,   0x3fffff,   0x7fffff,   0xffffff,
                            0x1ffffff,  0x3ffffff,  0x7ffffff,  0xfffffff,
                            0x1fffffff, 0x3fffffff, 0x7fffffff, 0xffffffff};

static void getversion(char  *fn, uint32_t  *tver)
{
    char    buf[64] = {0};
    char    name[NAME_MAX_LEN] = {0};
    int     fd = 0, ret = 0;
    char   *value = NULL;
    uint32_t trust_ver = 0;

    if (NULL == fn || NULL == tver) {
        printf("input paramater wrong!\n");
        return;
    }
    if (strlen(fn) > NAME_MAX_LEN) {
        printf("fn is invalid!\n");
        return;
    }
    strcpy(name, fn);
    if (name[strlen(fn) - 1] != '/') {
        strcat(name,"/");
    }
    strcat(name, "version.cfg");
    fd = open(name, O_RDONLY);
    if (fd < 0) {
        printf("open version file failed!\n");
        return;
    }
    memset(buf, 0, sizeof(buf));
    ret = read(fd, buf, sizeof(buf));
    if (ret < 0) {
        printf("read version file failed!\n");
        goto error;
    }
    value = buf;
    my_strsep(&value, "=");
    trust_ver = atoi(value);
    if (trust_ver > TRUSTED_VERSION_MAX) {
        trust_ver = TRUSTED_VERSION_MAX;
    }
    printf("trust_ver = %d \n", trust_ver);
    *tver = s_tver_arr[trust_ver];
    printf("tver = 0x%x\n", *tver);
error:
    close(fd);
    return;
}

static void *load_file(const char *fn, unsigned *num)
{
    size_t n, j = 0; uint8_t *buf = 0;
    FILE *fi = fopen(fn, "rb");
    if (fi) {
        fseek(fi, 0, SEEK_END);
        n = ftell(fi);
        if (n) {
            fseek(fi, 0, SEEK_SET);
            buf = (uint8_t*)malloc(n);
            if (buf) j = fread(buf, 1, n, fi);
        }
        fclose(fi);
    }
    if (num) *num = j;
    return buf;
}
/*
 *  this function compare the first four bytes in image and return 1 if equals to
 *  MODEM_MAGIC
 */
static int is_packed_modem_image(char *data)
{
	if (memcmp(data, MODEM_MAGIC, sizeof(MODEM_MAGIC)))
		return 0;
	return 1;
}

/*
 *  this function parse new packed modem image and return modem code offset and length
 */
static void get_modem_info(unsigned char *data, unsigned int *code_offset, unsigned int *code_len)
{
	unsigned int offset = 0, hdr_offset = 0, length = 0;
	unsigned char hdr_buf[MODEM_HDR_SIZE << 3] = {0};
	unsigned char read_len;
	unsigned char result = 0; // 0:OK, 1:not find, 2:some error occur
	data_block_header_t *hdr_ptr = NULL;

	read_len = sizeof(hdr_buf);
	memcpy(hdr_buf, data, read_len);

    do {
      if (!hdr_offset) {
        if (memcmp(hdr_buf, MODEM_MAGIC, sizeof(MODEM_MAGIC))) {
          result = 2;
          printf("old image format!\n");
          break;
        }

        hdr_ptr = (data_block_header_t *)hdr_buf + 1;
        hdr_offset = MODEM_HDR_SIZE;
      } else {
        hdr_ptr = (data_block_header_t *)hdr_buf;
      }

      data_block_header_t* endp
          = (data_block_header_t*)(hdr_buf + sizeof hdr_buf);
      int found = 0;
      while (hdr_ptr < endp) {
        uint32_t type = (hdr_ptr->type_flags & 0xff);
        if (SCI_TYPE_MODEM_BIN == type) {
          found = 1;
          break;
        }

        /*  There is a bug (622472) in MODEM image generator.
         *  To recognize wrong SCI headers and correct SCI headers,
         *  we devise the workaround.
         *  When the MODEM image generator is fixed, remove #if 0.
         */
#if 0
        if (hdr_ptr->type_flags & MODEM_LAST_HDR) {
          result = 2;
          MODEM_LOGE("no modem image, error image header!!!\n");
          break;
        }
#endif
        hdr_ptr++;
      }
      if (!found) {
        result = 2;
        printf("no MODEM exe found in SCI header!");
      }

      if (result != 1) {
        break;
      }
    } while (1);

    if (!result) {
      offset = hdr_ptr->offset;
      if (hdr_ptr->type_flags & MODEM_SHA1_HDR) {
        offset += MODEM_SHA1_SIZE;
      }
      length = hdr_ptr->length;
    }

	*code_offset = offset;
	*code_len = length;
}

int write_padding(int fd, unsigned pagesize, unsigned itemsize)
{
	unsigned pagemask = pagesize - 1;
	unsigned int count;
	memset(padding, 0xff, sizeof(padding));
	if ((itemsize & pagemask) == 0) {
		return 0;
	}

	count = pagesize - (itemsize & pagemask);
	//printf("need to padding %d byte,%d,%d\n",count,itemsize%8,(itemsize & pagemask));
	if (write(fd, padding, count) != count) {
		return -1;
	} else {
		return 0;
	}
}

void usage(void)
{
    printf("============================================================= \n");
    printf("Usage: \n");
    printf("$./sprd_sign <filename> <config_path> <pss flag> \n");
    printf("------------------------------------------------------------- \n");
    printf("-filename     --the image to be singed \n");
    printf("------------------------------------------------------------- \n");
    printf("-config_path  --the path that contains keys & version configs \n");
    printf("------------------------------------------------------------- \n");
    printf("-pss flag     --the flag of pss or pkcs15 \n");
    printf("============================================================= \n");
}

/*
*  this function only sign the img
*/

int sprd_signimg(char *img, char *key_path, char *pss_flag)
{
	int i;
	int fd = 0;
	int img_len;
	char *key[9] = { 0 };
//	unsigned pagesize = 512;
	char *input_data = NULL;
	char *output_data = NULL;
	char *img_name = NULL;
	char *payload_addr = NULL;
	unsigned int modem_offset = 0;
	unsigned int modem_len = 0;
    sys_img_header *p_header = NULL;
    uint32_t tversion = 0;
	uint8_t certhash[HASH_BYTE_LEN] = {0};
	char pubkeyToVerifyVbmeta[SPRD_RSA4096PUBKLEN];

	memset(pubkeyToVerifyVbmeta, 0, sizeof(pubkeyToVerifyVbmeta));
	output_data = img;
	char *basec = strdup(img);
	img_name = basename(basec);

	printf("input image name is:%s\n",img);
	for (i = 0; i < 9; i++) {
		key[i] = (char *)malloc(NAME_MAX_LEN);
		if (key[i] == 0)
			goto fail;
		memset(key[i], 0, NAME_MAX_LEN);
		strcpy(key[i], key_path);
		if (key_path[strlen(key_path) - 1] != '/')
			key[i][strlen(key_path)] = '/';
		//printf("key[%d]= %s\n", i, key[i]);

	}

	strcat(key[0], "rsa2048_0_pub.pem");
	strcat(key[1], "rsa2048_1_pub.pem");
#if VBMETA_USE_2048
	strcat(key[2], "rsa2048_2_pub.bin");
#else
	strcat(key[2], "rsa4096_vbmeta_pub.bin");
#endif
	strcat(key[3], "rsa2048_0.pem");
	strcat(key[4], "rsa2048_1.pem");
	strcat(key[5], "vdsp_firmware_privatekey.pem");
	strcat(key[6], "vdsp_firmware_publickey.pem");
	strcat(key[7], "rsa2048_2_pub.pem");
	strcat(key[8], "rsa2048_2.pem");

    getversion(key_path, &tversion);

	sprdsignedimageheader sign_hdr;
	sprd_keycert keycert;
	sprd_contentcert contentcert;
	memset(&sign_hdr, 0, sizeof(sprdsignedimageheader));
	memset(&keycert, 0, sizeof(sprd_keycert));
	memset(&contentcert, 0, sizeof(sprd_contentcert));

	input_data = load_file(img, (unsigned *)&img_len);
	if (input_data == 0) {
		printf("warning:could not load img\n");
		return 0;
	}
	printf("img_len = %d\n", img_len);

    // Check input_data header
    p_header = (sys_img_header *)input_data;
    if (p_header->mMagicNum == IMG_BAK_HEADER) {
        printf("to be signed data size = %d \n", p_header->mImgSize);
        img_len = p_header->mImgSize + sizeof(sys_img_header);
    } else {
        printf("warning: no DHTB header,can't be signed! \n");
        goto fail;
    }
	payload_addr = input_data + sizeof(sys_img_header);

    if (is_packed_modem_image(payload_addr)) {
        printf("new packed modem image is found!\n");
        get_modem_info((unsigned char *)payload_addr, &modem_offset, &modem_len);
        payload_addr += modem_offset;
        sign_hdr.payload_size = modem_len;
        printf("modem offset is %d \n", modem_offset);
        printf("modem size is %d \n", modem_len);
        printf("update header imgsize \n");
        p_header = (sys_img_header *)input_data;
        p_header->is_packed     = 1;
        p_header->mFirmwareSize = modem_len;
    } else {
        sign_hdr.payload_size = p_header->mImgSize;
    }
	sign_hdr.payload_offset = sizeof(sys_img_header);
	sign_hdr.cert_offset = img_len + sizeof(sprdsignedimageheader);
	//printf("sign_hdr.cert_offset:0x%llx", sign_hdr.cert_offset);

	sprd_rsapubkey nextpubk;

	fd = open(output_data, O_CREAT | O_TRUNC | O_WRONLY | O_BINARY, 0644);
	if (fd == -1) {
		printf("error:could create '%s'\n", output_data);
		goto fail;
	}

	if (write(fd, input_data, img_len) != img_len)
		goto fail;

	if ((0 == memcmp("fdl1-sign.bin", img_name, strlen("fdl1-sign.bin")))
	    || (0 == memcmp("u-boot-spl-16k-sign.bin", img_name, strlen("u-boot-spl-16k-sign.bin")))
	    || (0 == memcmp("u-boot-spl-16k-emmc-sign.bin", img_name, strlen("u-boot-spl-16k-emmc-sign.bin")))
	    || (0 == memcmp("u-boot-spl-16k-ufs-sign.bin", img_name, strlen("u-boot-spl-16k-ufs-sign.bin")))
	    || (0 == memcmp("ddr_scan-sign.bin", img_name, strlen("ddr_scan-sign.bin")))) {
		printf("sign fdl1/spl: %s\n", img_name);
		keycert.certtype = CERTTYPE_KEY;
		keycert.version = tversion;
		keycert.type = Trusted_Firmware;
		sign_hdr.cert_size = sizeof(sprd_keycert);
		getpubkeyfrmPEM(&keycert.pubkey, key[0]);	/*pubk0 */
		getpubkeyfrmPEM(&nextpubk, key[1]);	/*pubk1 */
		printf("current pubk is: %s\n", key[0]);
		printf("nextpubk is: %s\n", key[1]);
		//dumpHex("payload:",payload_addr,512);
		cal_sha256((unsigned char *)payload_addr, sign_hdr.payload_size, keycert.hash_data);
		cal_sha256((unsigned char *)&nextpubk, SPRD_RSAPUBKLEN, keycert.hash_key);
		if(0 == strcmp(pss_flag,"pkcs15"))
		{
			calcSignature_pkcs1(keycert.hash_data, ((HASH_BYTE_LEN << 1) + 8), keycert.signature, key[3]);
		}
		else
		{
			printf("use pss format \n");
			cal_sha256(keycert.hash_data, ((HASH_BYTE_LEN << 1) + 8),certhash);
			calcSignature_pss(certhash, HASH_BYTE_LEN , keycert.signature, key[3]);
		}
		if (write(fd, &sign_hdr, sizeof(sprdsignedimageheader)) != sizeof(sprdsignedimageheader))
			goto fail;
		if (write(fd, &keycert, sizeof(sprd_keycert)) != sizeof(sprd_keycert))
			goto fail;

	} else if ((0 == memcmp("fdl2-sign.bin", img_name, strlen("fdl2-sign.bin")))
		   || (0 == memcmp("u-boot-sign.bin", img_name, strlen("u-boot-sign.bin")))
		   || (0 == memcmp("u-boot_autopoweron-sign.bin", img_name, strlen("u-boot_autopoweron-sign.bin")))
           || (0 == memcmp("u-boot-dtb-sign.bin",img_name,strlen("u-boot-dtb-sign.bin")))) {
		printf("sign fdl2/uboot: %s\n", img_name);
		keycert.certtype = CERTTYPE_KEY;
		keycert.version = tversion;
		keycert.type = Trusted_Firmware;
		printf("keycert version is: %d\n", keycert.version);
		sign_hdr.cert_size = sizeof(sprd_keycert);
		getpubkeyfrmPEM(&keycert.pubkey, key[1]);	/*pubk1 */
		getpubkeyToVerifyVbmeta((char *)pubkeyToVerifyVbmeta, key[2]);	/*pubk2 */
		printf("current pubk is: %s\n", key[1]);
		printf("pubkeyToVerifyVbmeta is: %s\n", key[2]);
		cal_sha256((unsigned char *)payload_addr, sign_hdr.payload_size, keycert.hash_data);

		//dumpHex("pubkeyToVerifyVbmeta:",(unsigned char *)(pubkeyToVerifyVbmeta),SPRD_RSA4096PUBKLEN);

#if VBMETA_USE_2048
		cal_sha256((unsigned char *)pubkeyToVerifyVbmeta, SPRD_RSA2048PUBKLEN, keycert.hash_key);
#else
		cal_sha256((unsigned char *)pubkeyToVerifyVbmeta, SPRD_RSA4096PUBKLEN, keycert.hash_key);
#endif
		//dumpHex("pubkey hash ToVerifyVbmeta:",(unsigned char *)(keycert.hash_key),HASH_BYTE_LEN);
		if(0 == strcmp(pss_flag,"pkcs15"))
		{
			calcSignature_pkcs1(keycert.hash_data, ((HASH_BYTE_LEN << 1) + 8), keycert.signature, key[4]);
		}
		else
		{
			printf("use pss format \n");
			cal_sha256(keycert.hash_data, ((HASH_BYTE_LEN << 1) + 8),certhash);
			calcSignature_pss(certhash,HASH_BYTE_LEN, keycert.signature, key[4]);
		}
		/*
		if(write_padding(fd,pagesize,img_len))
			goto fail;
		*/
		if (write(fd, &sign_hdr, sizeof(sprdsignedimageheader)) != sizeof(sprdsignedimageheader))
			goto fail;
		if (write(fd, &keycert, sizeof(sprd_keycert)) != sizeof(sprd_keycert))
			goto fail;

	} else if ((0 == memcmp("tos-sign.bin", img_name, strlen("tos-sign.bin"))) \
            || (0 == memcmp("teecfg-sign.bin", img_name, strlen("teecfg-sign.bin"))) \
            || (0 == memcmp("sml-sign.bin", img_name, strlen("sml-sign.bin"))) \
            || (0 == memcmp("mobilevisor-sign.bin",img_name,strlen("mobilevisor-sign.bin"))) \
            || (0 == memcmp("secvm-sign.bin",img_name,strlen("secvm-sign.bin"))) \
            || (0 == memcmp("mvconfig-sign.bin",img_name,strlen("mvconfig-sign.bin")))) {
		printf("sign tos/teecfg/sml: %s\n", img_name);
		contentcert.certtype = CERTTYPE_CONTENT;
		contentcert.version = tversion;
		contentcert.type = Trusted_Firmware;
		sign_hdr.cert_size = sizeof(sprd_contentcert);
		getpubkeyfrmPEM(&contentcert.pubkey, key[1]);	/*pubk1 */
		printf("current pubk is: %s\n", key[1]);
		cal_sha256((unsigned char *)payload_addr, sign_hdr.payload_size, contentcert.hash_data);
		if(0 == strcmp(pss_flag,"pkcs15"))
		{
			calcSignature_pkcs1(contentcert.hash_data, (HASH_BYTE_LEN + 8), contentcert.signature, key[4]);
		}
		else
		{
			printf("use pss format \n");
			cal_sha256(contentcert.hash_data, (HASH_BYTE_LEN + 8),certhash);
			calcSignature_pss(certhash, HASH_BYTE_LEN, contentcert.signature, key[4]);
		}
		if (write(fd, &sign_hdr, sizeof(sprdsignedimageheader)) != sizeof(sprdsignedimageheader))
			goto fail;
		if (write(fd, &contentcert, sizeof(sprd_contentcert)) != sizeof(sprd_contentcert))
			goto fail;
	} else if (0 == memcmp("faceid_fw-sign.bin", img_name, strlen("faceid_fw-sign.bin"))){
		printf("sign firmware: %s\n", img_name);
		contentcert.certtype = CERTTYPE_CONTENT;
		contentcert.version = tversion;
		contentcert.type = Trusted_Firmware;
		sign_hdr.cert_size = sizeof(sprd_contentcert);
		getpubkeyfrmPEM(&contentcert.pubkey, key[6]);	/*pubk6 */
		printf("current pubk is: %s\n", key[6]);
		cal_sha256((unsigned char *)payload_addr, sign_hdr.payload_size, contentcert.hash_data);
		if(0 == strcmp(pss_flag,"pkcs15"))
		{
			printf("use pkcs15 format \n");
			calcSignature_pkcs1(contentcert.hash_data, (HASH_BYTE_LEN + 8), contentcert.signature, key[5]);
		}
		else
		{
			printf("use pss format \n");
			cal_sha256(contentcert.hash_data, (HASH_BYTE_LEN + 8),certhash);
			calcSignature_pss(certhash, HASH_BYTE_LEN, contentcert.signature, key[5]);
		}
		if (write(fd, &sign_hdr, sizeof(sprdsignedimageheader)) != sizeof(sprdsignedimageheader))
			goto fail;
		if (write(fd, &contentcert, sizeof(sprd_contentcert)) != sizeof(sprd_contentcert))
			goto fail;
	} else {
		printf("sign boot/modem: %s\n", img_name);
		contentcert.certtype = CERTTYPE_CONTENT;
		contentcert.version = tversion;
		contentcert.type = Non_Trusted_Firmware;
		printf("contentcert version is: %d\n", contentcert.version);
		sign_hdr.cert_size = sizeof(sprd_contentcert);
		getpubkeyfrmPEM(&contentcert.pubkey, key[7]);	/*pubk2 */
		printf("current pubk is: %s\n", key[7]);
		cal_sha256(payload_addr, sign_hdr.payload_size, contentcert.hash_data);
		calcSignature_pkcs1(contentcert.hash_data, (HASH_BYTE_LEN + 8), contentcert.signature, key[8]);
		if (write(fd, &sign_hdr, sizeof(sprdsignedimageheader)) != sizeof(sprdsignedimageheader))
			goto fail;
		if (write(fd, &contentcert, sizeof(sprd_contentcert)) != sizeof(sprd_contentcert))
			goto fail;

	}
    free(input_data);
	close(fd);
	return 1;

fail:
	printf("sign %s failed!!!\n", img);
	if(unlink(output_data) == -1){
		printf("unlink error!\n");
	}
	if(fd != -1){
		close(fd);
        }
	for (i = 0; i < 7; i++) {
		if (key[i] != 0)
			free(key[i]);
	}

	if (basec != 0)
		free(basec);
    if (input_data != NULL) free(input_data);
	return 0;

}

int main(int argc, char **argv)
{
	if (argc != 4) {
		usage();
		return 0;
	}
	char *cmd1 = argv[1];	//img name
	char *cmd2 = argv[2];	//key documount
	char *cmd3 = argv[3];   //pss flag
	sprd_signimg(cmd1, cmd2, cmd3);

}
