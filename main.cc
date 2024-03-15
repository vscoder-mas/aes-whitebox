#include <string.h>
#include <stdio.h>
#include <iostream>
#include <string>
#include "aes_whitebox.h"
#include "base64url.hpp"
#include "gzip.hpp"

/**
 * g++ main.cc aes_whitebox.cc -o main.out -std=c++11 -lz
*/
int main(int argc, char const *argv[]) {
    /* code */
    const uint8_t AES128_CFB_TEST_IV[16] = {'e', 'a', '5', '6', 'c', 'a', '8', '3', '7', '4', 'd', '5', 'e', '5', '9', '2'};

    char TEST_PLAIN[] = "hello world !";
    uint8_t *unzip = NULL;
    auto unzip_size = mostars::gzip::compress((const char *)TEST_PLAIN, strlen(TEST_PLAIN), &unzip);

    uint32_t left = unzip_size % 16;
    uint32_t padding = (16 - left);
    size_t block = unzip_size + padding;
    uint8_t *cipher = (uint8_t *) malloc(block);
    memset(cipher, 0, block);

    aes_whitebox_encrypt_cfb(AES128_CFB_TEST_IV, unzip, block, cipher);
    std::string en_aes(reinterpret_cast<const char *>(cipher), block);
    std::string en_base64 = std::move(base64_encode_url(en_aes));
    std::cout << en_base64 << std::endl;

    if (NULL != cipher) {
        free(cipher);
        cipher = NULL;
    }

    if (NULL != unzip) {
        free(unzip);
        unzip = NULL;
    }

    return 0;
}

