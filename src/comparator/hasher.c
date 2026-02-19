#define _XOPEN_SOURCE 700

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

#include "hasher.h"

int calculate_sha256(const char *filepath, char output[65]) {

    FILE *file = fopen(filepath, "rb");
    if (!file)
        return -1;

    SHA256_CTX sha_ctx;
    SHA256_Init(&sha_ctx);

    unsigned char buffer[4096];
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        SHA256_Update(&sha_ctx, buffer, bytes_read);
    }

    fclose(file);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha_ctx);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }

    output[64] = '\0';

    return 0;
}
