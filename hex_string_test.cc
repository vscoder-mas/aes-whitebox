#include <stdio.h>
#include <string.h>
#include <iostream>
#include <string>

//"0123456789ABCDEF"
static uint8_t HEX_CHAR[16];

static char *HexString(uint8_t *source, const size_t length) {
    char *ret = (char *) malloc(length * 2 + 1);
    ret[length * 2] = '\0';
    char *ret_p = ret;

    uint8_t *p = reinterpret_cast<uint8_t *>(source);
    for (size_t i = 0; i < length; i++) {
        uint8_t index = (*p >> 4) & 0x0F;
        *ret = HEX_CHAR[index];
        ret++;
        index = (*p) & 0x0F;
        *ret = HEX_CHAR[index];
        ret++;
        p++;
    }

    return ret_p;
}

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
    //初始化模版字符串 0123456789ABCDEF
    size_t j = 0;
    for (size_t i = 0; i < 16; i++) {
        if (i < 10) {
            HEX_CHAR[i] = i + 48;
        } else {
            HEX_CHAR[i] = j + 65;
            j++;
        }
    }

    const char *aes128_key = "60bd4de930f4f63d";
    char *hex_string_key = HexString((uint8_t *)aes128_key, 16);

    for (int i = 0; i < strlen(hex_string_key); i++) {
        printf("%c", hex_string_key[i]);
    }

    printf("\n");

    //16 + 1
    uint8_t key[17] = "\0";
    memset(key, 0, sizeof(key));
    read_hex(hex_string_key, key, 16, "key");
    std::cout << "- hex_string_key length:" << strlen(hex_string_key) << std::endl;
    printf("- key:%s, key.length:%zu\n", key, sizeof(key));
    return 0;
}
