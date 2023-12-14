#include "imgheaderinsert.h"

#include "mincrypt/sha256.h"

void do_sha256(uint8_t *data,int bytes_num,unsigned char *hash)
{
    SHA256_CTX ctx;
    const uint8_t* sha;

    SHA256_init(&ctx);
    SHA256_update(&ctx, data, bytes_num);
    sha = SHA256_final(&ctx);

    memcpy(hash,sha,SHA256_DIGEST_SIZE);
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


static void usage(void)
{
    printf("============================================================================= \n");
    printf("Usage: \n");
    printf("$./imgheaderinsert <filename> <add_payloadhash> <remove_flag> \n");
    printf("----------------------------------------------------------------------------- \n");
    printf("-filename              --the image to be inserted with sys_img_header \n");
    printf("----------------------------------------------------------------------------- \n");
    printf("-add_payloadhash = 1   --add payload hash when secure boot is disabled \n");
    printf("                 = 0   --payload hash isn't needed when secure boot is enabled\n");
    printf("----------------------------------------------------------------------------- \n");
    printf("-remove_flag     = 1   --delete the original file \n");
    printf("============================================================================= \n");
}

void dumpHex(const char *title, uint8_t * data, int len)
{
    int i, j;
    int N = len / 16 + 1;
    printf("%s %d bytes", title, len);
    for (i = 0; i < N; i++) {
        printf("\r\n");
        for (j = 0; j < 16; j++) {
            if (i * 16 + j >= len)
                goto end;
            printf("%02x", data[i * 16 + j]);
        }
    }
end:    printf("\r\n");
    return;
}

int main(int argc, char* argv[])
{
    char        filename[FILE_NAME_SIZE] = "0";
    char        imagename[FILE_NAME_SIZE] = "0";
    char        suffix[10] = "0";
    char        flag = '.';
    char       *namesuffix = "-sign";
    uint8_t    *payload = NULL, *p_data = NULL;
    char       *start = NULL;
    char       *end = NULL;
    char       *ptr = NULL;
    int         fd = -1;
    int         addPayloadHash = 0;
    int         remove_flag = 0;
    uint32_t    imgpadsize = 0;  //raw size + padding
    uint32_t    vb_pad = 0;
    int         is_signed = 0;
    sys_img_header   img_h;
    sys_img_header  *p_hdr = NULL;

    // Input param check
    if (argc != 4) {
        usage();
        return 1;
    }
    // Init
    memset(&img_h,    0, sizeof(img_h));
    memset(filename,  0, sizeof(filename));
    memset(imagename, 0, sizeof(imagename));
    img_h.mVersion = 1;
    img_h.mMagicNum = IMG_BAK_HEADER;
    strcpy(filename, argv[1]);
    addPayloadHash = atoi(argv[2]);
    remove_flag = atoi(argv[3]);
    // Fix output image name
    strcpy(imagename, filename);
    if (strstr(filename, namesuffix) != NULL) {
        printf("Input file name contain -sign. \n");
        if (strstr(filename, VBMETA) != NULL) {
            printf("No need re-sign for vbmeta. \n");
            return 0;
        } else {
            is_signed = 1;
        }
    } else {
        start = imagename;
        end = strrchr(start, flag);
        if (end == NULL) {
            return 1;
        }
        memcpy(suffix, end, strlen(end)+1);
        imagename[end-start] = '\0';
        strcat(imagename, namesuffix);
        strcat(imagename, suffix);
    }
    printf("output name: %s \n", imagename);
    // Load file
    payload = load_file(filename, &imgpadsize);
    if(payload == NULL) {
        printf("warning: could not load %s \n", filename);
        return 1;
    }
    printf("imgpadsize = %d \n", imgpadsize);
    // Check payload header
    p_hdr = (sys_img_header *)payload;
    if (is_signed == 1 && p_hdr->mMagicNum == IMG_BAK_HEADER) {
        printf("signed image size = %d \n", p_hdr->mImgSize);
        p_data = payload + sizeof(sys_img_header);
        img_h.mImgSize = p_hdr->mImgSize;
    } else {
        printf("raw data. \n");
        img_h.mImgSize = imgpadsize;
        p_data = payload;
    }
    if (addPayloadHash == 1) {
        do_sha256(p_data, img_h.mImgSize, img_h.mPayloadHash);
    }
    // Write output file
    fd = open(imagename, O_CREAT | O_TRUNC | O_WRONLY | O_BINARY, 0644);
    if(fd == -1) {
        printf("warning: could not create '%s'\n", imagename);
        goto fail;
    }
    // for vbmeta image,will add hash at the end of partition
    if (strstr(filename, VBMETA) != NULL) {
        printf("for vbmeta img \n");
        vb_pad = VB_PARTITION_SIZE - imgpadsize - sizeof(img_h);
        ptr = (char*)malloc(vb_pad);
        if(ptr == 0) goto fail;
        memset(ptr, 0, vb_pad);
        if((uint32_t)write(fd, p_data, imgpadsize) != imgpadsize) goto fail;
        if((uint32_t)write(fd, ptr, vb_pad) != vb_pad) goto fail;
        if(write(fd, &img_h, sizeof(img_h)) != sizeof(img_h)) goto fail;
    } else {
        printf("for other img \n");
        if(write(fd, &img_h, sizeof(img_h)) != sizeof(img_h)) goto fail;
        if((uint32_t)write(fd, p_data, img_h.mImgSize) != img_h.mImgSize) goto fail;
    }
    free(payload);
    if (fd >= 0 ) close(fd);
    if (remove_flag == 1) remove(filename);
    if (ptr != NULL) free(ptr);
    return 0;
fail:
    free(payload);
    if (fd != -1) close(fd);
    if (ptr != NULL) free(ptr);
    printf("error: failed writing '%s'\n", imagename);
    return 1;
}

