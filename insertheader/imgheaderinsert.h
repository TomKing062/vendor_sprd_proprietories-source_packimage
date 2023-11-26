#ifndef _IMGHEADER_INSERT_H
#define _IMGHEADER_INSERT_H

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>

typedef signed char       int8_t;
typedef signed short      int16_t;
typedef signed int        int32_t;
typedef unsigned char     uint8_t;
typedef unsigned short    uint16_t;
typedef unsigned int      uint32_t;
//typedef unsigned long long uint64_t;

#define FILE_NAME_SIZE 2048

#define PADDING_MAX_SIZE   80*1024
#define VBMETA             "vbmeta"
#define VB_PARTITION_SIZE  1048576
#define IMG_BAK_HEADER     0x42544844

typedef struct
{
    uint32_t mMagicNum; // "BTHD"=="0x42544844"=="boothead"
    uint32_t mVersion; // 1
    uint8_t mPayloadHash[32];//sha256 hash value
    uint64_t mImgAddr; //image loaded address
    uint32_t mImgSize; //image size
    uint8_t reserved[512-(13*4)]; //reserved,make sure total size is 512B
}sys_img_header;

#endif
