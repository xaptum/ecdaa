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

#include "member_sign_ZZZ.h"

#include <ecdaa.h>

#include "tool_rand.h"

#define MAX_MESSAGE_SIZE 1024

int member_sign_ZZZ(const char* secret_key_file, const char* credential_file, const char* sig_out_file,
                        const char* message_file, const char* basename_file)
{
    // Read member secret key from disk
    struct ecdaa_member_secret_key_ZZZ sk;
    int ret = ecdaa_member_secret_key_ZZZ_deserialize_file(&sk, secret_key_file);
    if (0 != ret) {
        return ret;
    }

    // Read member credential from disk
    struct ecdaa_credential_ZZZ cred;
    ret = ecdaa_credential_ZZZ_deserialize_file(&cred, credential_file);
    if (0 != ret) {
        return ret;
    }

    // Read message file
    uint8_t message[MAX_MESSAGE_SIZE];
    int read_ret = ecdaa_read_from_file(message, sizeof(message), message_file);
    if (read_ret < 0) {
        return READ_FROM_FILE_ERROR;
    }
    uint32_t msg_len = (uint32_t)read_ret;

    // Read basename file (if requested)
    uint8_t *basename = NULL;
    uint32_t basename_len = 0;
    uint8_t basename_buffer[MAX_MESSAGE_SIZE];
    if (NULL != basename_file) {
        basename = basename_buffer;

        int read_ret = ecdaa_read_from_file(basename_buffer, sizeof(basename_buffer), basename_file);
        if (read_ret < 0) {
            return READ_FROM_FILE_ERROR;
        }
        basename_len = (uint32_t)read_ret;
    }

    // Create signature
    struct ecdaa_signature_ZZZ sig;
    if (0 != ecdaa_signature_ZZZ_sign(&sig, message, msg_len, basename, basename_len, &sk, &cred, tool_rand)) {
        return SIGNING_ERROR;
    }

    // Write signature to file
    int has_nym = basename_len != 0;
    ecdaa_signature_ZZZ_serialize_file(sig_out_file, &sig, has_nym);

    return SUCCESS;
}
