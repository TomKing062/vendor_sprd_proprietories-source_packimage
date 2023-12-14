#ifndef PK1_H
#define PK1_H

void invert_char(unsigned char *src, int len);

int get_rand_bytes(unsigned char *buf, int num);

int padding_add_PKCS1_type_1(unsigned char *to, int tlen, const unsigned char *from, int flen);

int padding_check_PKCS1_type_1(unsigned char *to, int tlen, const unsigned char *from, int flen, int num);

int padding_add_PKCS1_type_2(unsigned char *to, int tlen, const unsigned char *from, int flen);

int padding_check_PKCS1_type_2(unsigned char *to, int tlen, const unsigned char *from, int flen, int num);

#endif
