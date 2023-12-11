#include <stdio.h>
#include <string.h>
#include <iostream>
#include "aes_whitebox.h"

static void read_hex(const char *in, uint8_t* v, size_t size, const char* param_name) {
  if (strlen(in) != size << 1) {
    printf("Invalid param %s (got %ld, expected %ld)\n",
        param_name, strlen(in), size << 1);
  }

  for (size_t i = 0; i < size; i++) {
    sscanf(in + i * 2, "%2hhx", v + i);
  }
}

int main(int argc, char const *argv[]) {
    /* code */
    //sizeof(TEST_PLAIN) 有 \0, 多一个字节，所以加密是传 strlen(TEST_PLAIN)=13
    char TEST_PLAIN[] = "hello world !";
    // char TEST_PLAIN[13] = {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', ' ', '!'};
    // char TEST_PLAIN[] = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
    char AES128_CFB_TEST_CIPHER[] = "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6";
    char AES128_CFB_TEST_IV[] = "000102030405060708090a0b0c0d0e0f";

    uint8_t plain[4*16], iv_or_nonce[16], cipher[4*16], output[4*16];
    void (*encrypt)(const uint8_t iv[16], const uint8_t* m,
        size_t len, uint8_t* c) = NULL;
    void (*decrypt)(const uint8_t iv[16], const uint8_t* m,
        size_t len, uint8_t* c) = NULL;

    // read_hex(TEST_PLAIN, plain, 4*16, "plain");
    read_hex(AES128_CFB_TEST_IV, iv_or_nonce, 16, "iv-or-nonce");
    // read_hex(AES128_CFB_TEST_CIPHER, cipher, 4*16, "cipher");

    encrypt = &aes_whitebox_encrypt_cfb;
    decrypt = &aes_whitebox_decrypt_cfb;

    // 因为 TEST_PLAIN(hexstring) 转换成了 plain(二进制)，plain 的 length=64(sizeof(plain))，没有‘\0’，不存在包含 ‘\0’ 加密
    // (*encrypt)(iv_or_nonce, plain, sizeof(plain), output);
    // printf("Encrypt, vector #1 ret:%d\n", memcmp(output, cipher, sizeof(cipher)));
    // (*decrypt)(iv_or_nonce, cipher, sizeof(cipher), output);
    // printf("Decrypt, vector #1 ret:%d\n", memcmp(output, plain, sizeof(plain)));

    uint8_t cipher1[16] = {0};
    // (*encrypt)(iv_or_nonce, (uint8_t *)TEST_PLAIN, sizeof(TEST_PLAIN), cipher1);
    (*encrypt)(iv_or_nonce, (uint8_t *)TEST_PLAIN, strlen(TEST_PLAIN), cipher1);
    uint8_t origin[16] = {0};
    (*decrypt)(iv_or_nonce, cipher1, sizeof(cipher1), origin);

    // for (int i = 0; i < sizeof(TEST_PLAIN); i++) {
    for (int i = 0; i < strlen(TEST_PLAIN); i++) {
        printf("%c\n", origin[i]);
    }

    return 0;
}



