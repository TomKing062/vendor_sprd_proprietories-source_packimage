#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#pragma pack(4)

#define AVB_MAGIC_LEN 4
#define AVB_RELEASE_STRING_SIZE 48

typedef struct AvbVBMetaImageHeader {
    uint8_t magic[AVB_MAGIC_LEN];
    uint32_t required_libavb_version_major;
    uint32_t required_libavb_version_minor;
    uint64_t authentication_data_block_size;
    uint64_t auxiliary_data_block_size;
    uint32_t algorithm_type;
    uint64_t hash_offset;
    uint64_t hash_size;
    uint64_t signature_offset;
    uint64_t signature_size;
    uint64_t public_key_offset;
    uint64_t public_key_size;
    uint64_t public_key_metadata_offset;
    uint64_t public_key_metadata_size;
    uint64_t descriptors_offset;
    uint64_t descriptors_size;
    uint64_t rollback_index;
    uint32_t flags;
    uint32_t rollback_index_location;
    uint8_t release_string[AVB_RELEASE_STRING_SIZE];
    uint8_t reserved[80];
} AvbVBMetaImageHeader;

typedef struct AvbChainPartitionDescriptor {
    uint64_t tag;
    uint64_t num_bytes_following;
    uint32_t rollback_index_location;
    uint32_t partition_name_len;
    uint32_t public_key_len;
    uint32_t flags;
    uint8_t reserved[60];
} AvbChainPartitionDescriptor;

uint32_t reverse_uint32(uint32_t x) {
    uint32_t result = 0;

    result |= (x & 0x000000FF) << 24;
    result |= (x & 0x0000FF00) << 8;
    result |= (x & 0x00FF0000) >> 8;
    result |= (x & 0xFF000000) >> 24;
    return result;
}

uint64_t reverse_uint64(uint64_t x) {
    uint64_t result = 0;

    result |= (x & 0x00000000000000FF) << 56;
    result |= (x & 0x000000000000FF00) << 40;
    result |= (x & 0x0000000000FF0000) << 24;
    result |= (x & 0x00000000FF000000) << 8;
    result |= (x & 0x000000FF00000000) >> 8;
    result |= (x & 0x0000FF0000000000) >> 24;
    result |= (x & 0x00FF000000000000) >> 40;
    result |= (x & 0xFF00000000000000) >> 56;
    return result;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "No input file\n");
        return 0;
    }
    char* meta_path = argv[1];
    // Read the file content into a byte array
    FILE* file = fopen(meta_path, "rb");
    if (file == NULL) {
        fprintf(stderr, "Cannot open file\n");
        return 0;
    }
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    unsigned char* buffer0 = (unsigned char*)malloc(file_size);
    unsigned char* buffer = buffer0;
    fread(buffer0, 1, file_size, file);
    fclose(file);

    FILE* fo = fopen("sign_vbmeta.sh", "wb");
    if (fo == NULL) {
        fprintf(stderr, "Cannot create file\n");
        return 0;
    }

    if (*(uint32_t*)buffer0 == 0x42544844) buffer += 0x200;
    AvbVBMetaImageHeader* vbheader = (AvbVBMetaImageHeader*)buffer;
    uint32_t algorithm_type = reverse_uint32(vbheader->algorithm_type);
    int rsa = 256 * (algorithm_type < 4 ? 1 : 2);
    if (algorithm_type < 1 || algorithm_type > 6) return 1;
    int algorithm = 1024 * (int)pow(2, algorithm_type < 4 ? algorithm_type : (algorithm_type - 3));
    fprintf(fo, "python avbtool make_vbmeta_image --key rsa%d_vbmeta.pem --algorithm SHA%d_RSA%d \\\n", algorithm, rsa, algorithm);
    AvbChainPartitionDescriptor* chainheader = (AvbChainPartitionDescriptor*)(buffer + sizeof(AvbVBMetaImageHeader) + reverse_uint64(vbheader->authentication_data_block_size));
    uint64_t tag = reverse_uint64(chainheader->tag);
    while (1)
    {
        uint32_t rollback_index_location = reverse_uint32(chainheader->rollback_index_location);
        uint32_t partition_name_len = reverse_uint32(chainheader->partition_name_len);
        uint32_t public_key_len = reverse_uint32(chainheader->public_key_len);
        char* name = (char*)malloc(partition_name_len + 1);
        if (name == 0) return 1;
        memcpy(name, (unsigned char*)chainheader + sizeof(AvbChainPartitionDescriptor), partition_name_len);
        name[partition_name_len] = '\0';
        char* key_path = (char*)malloc(partition_name_len + 64);
        if (key_path == 0) return 1;
        sprintf(key_path, "rsa%d_%s_pub.bin", algorithm, name);
        printf("extracted rsa%d_%s_pub.bin\n", algorithm, name);
        FILE* key_file = fopen(key_path, "wb");
        if (key_file == NULL) {
            fprintf(stderr, "Cannot create file\n");
            return 0;
        }
        fwrite((unsigned char*)chainheader + sizeof(AvbChainPartitionDescriptor) + partition_name_len, 1, public_key_len, key_file);
        fclose(key_file);
        fprintf(fo, "--chain_partition %s:%u:keys/%s \\\n", name, rollback_index_location, key_path);

        uint32_t offset = ((sizeof(AvbChainPartitionDescriptor) + partition_name_len + public_key_len + 7) & 0xFFFFFFF8);
        chainheader = (AvbChainPartitionDescriptor*)((unsigned char*)chainheader + offset);
        free(name);
        free(key_path);
        if (tag != reverse_uint64(chainheader->tag)) break;
    }
    int padding = 0x1000;
    if (*(uint32_t*)buffer0 == 0x42544844) padding = *(uint32_t*)(buffer0 + 0x30);
    else if (*(uint32_t*)(buffer0 + 0xFFE00) == 0x42544844) padding = *(uint32_t*)(buffer0 + 0xFFE30);
    else printf("Warning: \"DHTB\" header not found.\n");
    fprintf(fo, "--padding_size %d --output vbmeta-sign-custom.img", padding);
    printf("padding_size %d\n", padding);
    fclose(fo);
    free(buffer0);
    return 0;
}