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

/**
 * 自定义生成 aes_whitebox_tables.cc 
 * g++ aes_whitebox_compiler.cc -o aes_whitebox_compiler -lntl -std=c++11
 * ./aes_whitebox_compiler aes128 60bd4de930f4f63d1234567890abcdef (key)
 * g++ demo.cc aes_whitebox_tables.cc aes_whitebox.cc -o demo.out -std=c++11
*/ 
int main(int argc, char const *argv[]) {
    /* code */
    //sizeof(TEST_PLAIN) 有 \0, 多一个字节，strlen(TEST_PLAIN)=13，所以要加密sizeof(TEST_PLAIN)，把\0也加密,
    //最好的方式是加密原数据也变成16的倍数，不够的补\0 !!!
    char TEST_PLAIN[] = "hello world !";
    // char TEST_PLAIN[13] = {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', ' ', '!'};
    // char TEST_PLAIN[] = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
    char AES128_CFB_TEST_CIPHER[] = "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6";
    // char AES128_CFB_TEST_IV[] = "000102030405060708090a0b0c0d0e0f";
    //自定义 IV，不需要反解 hexstring
    char AES128_CFB_TEST_IV[16] = {'e', 'a', '5', '6', 'c', 'a', '8', '3', '7', '4', 'd', '5', 'e', '5', '9', '2'};

    uint8_t plain[4*16], iv_or_nonce[16], cipher[4*16], output[4*16];
    void (*encrypt)(const uint8_t iv[16], const uint8_t* m,
        size_t len, uint8_t* c) = NULL;
    void (*decrypt)(const uint8_t iv[16], const uint8_t* m,
        size_t len, uint8_t* c) = NULL;

    // read_hex(TEST_PLAIN, plain, 4*16, "plain");
    memcpy(iv_or_nonce, AES128_CFB_TEST_IV, sizeof(AES128_CFB_TEST_IV));
    // read_hex(AES128_CFB_TEST_IV, iv_or_nonce, 16, "iv-or-nonce");
    // read_hex(AES128_CFB_TEST_CIPHER, cipher, 4*16, "cipher");

    encrypt = &aes_whitebox_encrypt_cfb;
    decrypt = &aes_whitebox_decrypt_cfb;

    // 因为 TEST_PLAIN(hexstring) 转换成了 plain(二进制)，plain 的 length=64(sizeof(plain))，没有‘\0’，不存在包含 ‘\0’ 加密
    // (*encrypt)(iv_or_nonce, plain, sizeof(plain), output);
    // printf("Encrypt, vector #1 ret:%d\n", memcmp(output, cipher, sizeof(cipher)));
    // (*decrypt)(iv_or_nonce, cipher, sizeof(cipher), output);
    // printf("Decrypt, vector #1 ret:%d\n", memcmp(output, plain, sizeof(plain)));

    // uint8_t cipher1[16] = {0};
    uint32_t left = sizeof(TEST_PLAIN) % 16;
    uint32_t padding = (16 - left);
    size_t block = sizeof(TEST_PLAIN) + padding;
    uint8_t *cipher1 = (uint8_t *) malloc(block);
    memset(cipher1, 0, block);
    (*encrypt)(iv_or_nonce, (uint8_t *)TEST_PLAIN, sizeof(TEST_PLAIN), cipher1);

    // uint8_t origin[16] = {0};
    uint8_t *origin = (uint8_t *) malloc(block);
    memset(origin, 0, block);
    (*decrypt)(iv_or_nonce, cipher1, block, origin);

    //非常重要!!! whitebox encrypt/decrypt 接口没有返回字节数，按 cipher's block，结尾会有乱码 ext:origin="hello world !t";
    //原因时 encrypt 时，传入的加密 size 是实际大小，所以超出的部分 decrypt 后，就成了未定义值。解决这种问题可以通过一下方式:
    //encrypt 的 size 也是 16 的倍数，然后 memset(0)，加密这个 size，即将补齐的字节也参与 encrypt; 当 decrypt 时，解密后的补齐
    //字节('\0')，视情况判断: 如果返回的字符串，那么需要将末尾的 \0 去掉(跨语言接口pb->bytes); 如果需要的是二进制数据，就返回补齐的 size-> block
    //详见: long-link: core_manager.cc
    std::string ret((char *)origin, strlen(TEST_PLAIN));
    std::cout << "- ret:" << ret << std::endl;
    //由于加密的是sizeof(TEST_PLAIN)，包含\0，所以下面的转字符串没有问题
    std::string ret1((const char *)origin);

    // for (int i = 0; i < sizeof(TEST_PLAIN); i++) {
    for (int i = 0; i < block; i++) {
        if (origin[i] == '\0') {
            printf("++++++++++++++++++\n");
        }
        
        printf("%c\n", origin[i]);
    }

    printf("\n");
    if (NULL != cipher1) {
      free(cipher1);
      cipher1 = NULL;
    }

    if (NULL != origin) {
      free(origin);
      origin = NULL;
    }

    return 0;
}



