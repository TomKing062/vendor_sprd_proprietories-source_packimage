
void *sec_memset(void *s, int c, unsigned int cnt)
{
	char *xs = s;

	while (cnt--)
		*xs++ = c;
	return s;
}

void *sec_memcpy(void *dest, const void *src, unsigned int count)
{
	char *tmp = dest;
	const char *s = src;

	while (count--)
		*tmp++ = *s++;
	return dest;
}

int sec_memcmp(const void *cs, const void *st, unsigned int count)
{
	const unsigned char *su1, *su2;
	int res = 0;

	for (su1 = cs, su2 = st; 0 < count; ++su1, ++su2, count--)
		if ((res = *su1 - *su2) != 0)
			break;
	return res;
}
