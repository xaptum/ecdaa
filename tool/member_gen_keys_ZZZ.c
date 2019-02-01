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

#include "member_gen_keys_ZZZ.h"

#include <string.h>

#include <ecdaa.h>

#include "tool_rand.h"

int member_gen_keys_ZZZ(const char* nonce, const char* public_key_file, const char* secret_key_file)
{
    // Generate member key-pair
    size_t nonce_length = strlen(nonce);

    struct ecdaa_member_public_key_ZZZ pk;
    struct ecdaa_member_secret_key_ZZZ sk;
    int ret = ecdaa_member_key_pair_ZZZ_generate(&pk, &sk, (uint8_t*)nonce, (uint32_t)nonce_length, tool_rand);
    if (0 != ret) {
        return KEY_CREATION_ERROR;
    }

    // Write public key to file
    ret = ecdaa_member_public_key_ZZZ_serialize_file(public_key_file, &pk);
    if (0 != ret)
        return ret;

    // Write secret key to file
    ret = ecdaa_member_secret_key_ZZZ_serialize_file(secret_key_file, &sk);
    if (0 != ret)
        return ret;

    return SUCCESS;
}
