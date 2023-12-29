#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Define a function to read an int from a byte array
int read_int(unsigned char* bytes, int offset) {
    int result = 0;
    for (int i = 0; i < 4; i++) {
        result |= bytes[offset + i] << (i * 8);
    }
    return result;
}

// Define a function to count the number of zeros in a byte array
int count_zeros(unsigned char* bytes, int length) {
    int count = 0;
    for (int i = 0; i < length; i++) {
        if (bytes[i] == 0) {
            count++;
        }
    }
    return count;
}

// Define a function to remove zeros from a byte array and return a string
char* remove_zeros(unsigned char* bytes, int length) {
    char* result = malloc(length + 1);
    int index = 0;
    for (int i = 0; i < length; i++) {
        if (bytes[i] != 0) {
            result[index] = bytes[i];
            index++;
        }
    }
    result[index] = '\0';
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
    unsigned char* buffer = (unsigned char*)malloc(file_size);
    fread(buffer, 1, file_size, file);
    fclose(file);

    FILE* fo = fopen("sign_vbmeta.sh", "wb");
    if (fo == NULL) {
        fprintf(stderr, "Cannot create log file\n");
        return 0;
    }

    fprintf(fo, "python avbtool make_vbmeta_image --key rsa4096_vbmeta.pem --algorithm SHA256_RSA4096 \\\n");
    int position = 0, position_ok = 0, position_index = 0, index = 0;
    while (1) {
        if (read_int(buffer, position) == 0x100000) {
            position_index = position - 0x60;
            for (int i = 0; i < 0x60; i++)
            {
                if (read_int(buffer, position_index + i) == 0x08040000)
                    index = *(buffer + position_index + i - 5);
            }
            // Search for name, take last 30 bytes and remove zero
            position -= 30;
            unsigned char* bytes = (unsigned char*)malloc(30);
            memcpy(bytes, buffer + position, 30);
            if (count_zeros(bytes, 30) > 10) {
                char* name = remove_zeros(bytes, 30);
                char* key_path = (char*)malloc(strlen(name) + 64);
                sprintf(key_path, "rsa4096_%s_pub.bin", name);
                FILE* key_file = fopen(key_path, "wb");
                if (key_file == NULL) {
                    fprintf(stderr, "Cannot create file\n");
                    return 0;
                }
                fwrite(buffer + position + 30, 1, 1032, key_file);
                fclose(key_file);
                position += 1032 + 30;
                position_ok = position;
                fprintf(fo, "--chain_partition %s:%d:keys/%s \\\n", name, index, key_path);
            }
            else {
                break;
            }
        }
        else if (position_ok) position += 1;
        else position += 4;
    }
    int padding = 0x1000;
    if(read_int(buffer, 0) == 0x42544844) padding = read_int(buffer, 0x30);
    else if(read_int(buffer, 0xFFE00) == 0x42544844) padding = read_int(buffer, 0xFFE30);
    else printf("Warning: \"DHTB\" header not found.\n");
    fprintf(fo, "--padding_size %d --output vbmeta-sign-custom.img", padding);
    fclose(fo);
    return 0;
}
