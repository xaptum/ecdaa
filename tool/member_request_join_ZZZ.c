/******************************************************************************
 *
 * Copyright 2018 Xaptum, Inc.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License
 *
 *****************************************************************************/

#include "member_request_join_ZZZ.h"

#include <string.h>

#include <ecdaa.h>

#include "tool_rand.h"

int member_request_join_ZZZ(const char* nonce, const char* public_key_file, const char* secret_key_file)
{
    // Generate member key-pair
    size_t nonce_len = strlen(nonce);
    if (nonce_len > 1048576) {    // 1MiB
        return NONCE_OVERFLOW;
    }
    int ret = ecdaa_member_key_pair_ZZZ_generate_file(public_key_file, secret_key_file, (uint8_t*)nonce, (uint32_t)nonce_len, tool_rand);
    if (0 != ret) {
        return ret;
    }

    return SUCCESS;
}
