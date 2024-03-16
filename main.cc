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
    uint8_t *zip = NULL;
    auto zip_size = mostars::gzip::compress((const char *)TEST_PLAIN, strlen(TEST_PLAIN), &zip);

    uint32_t left = zip_size % 16;
    uint32_t padding = (16 - left);
    size_t block = zip_size + padding;
    uint8_t *cipher = (uint8_t *) malloc(block);
    memset(cipher, 0, block);

    aes_whitebox_encrypt_cfb(AES128_CFB_TEST_IV, zip, block, cipher);
    std::string en_aes(reinterpret_cast<const char *>(cipher), block);
    std::string en_base64 = std::move(base64_encode_url(en_aes));
    std::cout << "- base64:" << en_base64 << std::endl;

    //decrypt
    std::string de_base64 = std::move(base64_decode_url(en_base64));
    uint8_t *origin = (uint8_t *) malloc(de_base64.size());
    memset(origin, 0, de_base64.size());
    aes_whitebox_decrypt_cfb(AES128_CFB_TEST_IV, (const uint8_t *)de_base64.c_str(), de_base64.size(), origin);
    uint8_t *unzip = NULL;
    auto unzip_size = mostars::gzip::decompress((char *)origin, de_base64.size(), &unzip);
    std::string output((const char *)unzip, unzip_size);
    std::cout << "- output:" << output << std::endl;

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

