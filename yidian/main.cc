#include <iostream>
#include <string>
#include <string.h>
#include "aes_whitebox_testreqx.h"
#include "aes_whitebox_testrspx.h"
#include "aes_whitebox_prodreqx.h"
#include "aes_whitebox_prodrspx.h"
#include "base64url.hpp"
#include "gzip.hpp"

#define AES_OPERATION(NAMESPACE, OPER)                                                             \
    whitebox::utils::WBUint8Buf_16 buffer((const uint8_t *) de_base64.c_str(), de_base64.size());  \
    auto cipher = NAMESPACE::OPER(buffer);

std::string unzip(whitebox::utils::WBUint8Buf_16 &_buffer, size_t _length, const char *_gz) {
    std::string output = "";
    if (strcmp(_gz, "true") == 0) {
        uint8_t *unzip = NULL;
        auto length = mostars::gzip::decompress((const char *)_buffer.BuffPtr(), _length, &unzip);
        output = std::string((const char *)unzip, length);
    } else {
        output = std::string((const char *)_buffer.BuffPtr(), _length);
    }

    return output;
}

/**
 * g++ main.cc aes_whitebox_testreqx.cc aes_whitebox_testrspx.cc aes_whitebox_prodreqx.cc aes_whitebox_prodrspx.cc -o main.out -std=c++11 -lz
*/
int main(int argc, char const *argv[]) {
    /* code */
    const char *test_req = "testreq";
    const char *test_rsp = "testrsp";
    const char *prod_req = "prodreq";
    const char *prod_rsp = "prodrsp";

    const char *oper = argv[1];
    const char *input = argv[2];
    const char *gz = argv[3];

    std::string en_base64(input);
    std::string de_base64 = base64_decode_url(en_base64);
    std::string output = "";

    if (strcmp(oper, test_req) == 0) {
        AES_OPERATION(white_box_testreq, cfb_decrypt)
        output = std::move(unzip(cipher, de_base64.size(), gz));
    } else if (strcmp(oper, test_rsp) == 0) {
        AES_OPERATION(white_box_testrsp, cfb_decrypt)
        output = std::move(unzip(cipher, de_base64.size(), gz));
    } else if (strcmp(oper, prod_req) == 0) {
        AES_OPERATION(white_box_prodreq, cfb_decrypt)
        output = std::move(unzip(cipher, de_base64.size(), gz));
    } else if (strcmp(oper, prod_rsp) == 0) {
        AES_OPERATION(white_box_prodrsp, cfb_decrypt)
        output = std::move(unzip(cipher, de_base64.size(), gz));        
    }
    
    std::cout << output << std::endl;
    return 0;
}



