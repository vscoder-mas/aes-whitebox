// Copyright 2019 AES WBC Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef AES_WHITEBOX_prodrsp_H_
#define AES_WHITEBOX_prodrsp_H_
#include <string>
#include <strstream>
#include "aes_uint8_buff.h"
namespace white_box_prodrsp
{
    whitebox::utils::WBUint8Buf_16 cfb_encrypt(whitebox::utils::WBUint8Buf_16& plain);
    whitebox::utils::WBUint8Buf_16 cfb_decrypt(whitebox::utils::WBUint8Buf_16& cyper);
}

#endif // AES_WHITEBOX_H_

