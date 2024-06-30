#ifndef SEC_STRING_H
#define SEC_STRING_H

#define TOLOWER(x) ((x) | 0x20)

void *sec_memset(void *s, int c, unsigned int cnt);
void *sec_memcpy(void *dest, const void *src, unsigned int count);
int sec_memcmp(const void *cs, const void *st, unsigned int count);


#endif /* !HEADER_AES_H */
