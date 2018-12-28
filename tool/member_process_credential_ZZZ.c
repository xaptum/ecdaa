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

#include "member_process_credential_ZZZ.h"

#include <ecdaa.h>

int member_process_credential_ZZZ(const char* member_public_key_file, const char* group_public_key_file,
                                       const char* credential_file, const char* credential_signature_file)
{
    // Read member public key from disk
    struct ecdaa_member_public_key_ZZZ pk;
    int ret = ecdaa_member_public_key_ZZZ_deserialize_no_check_file(&pk, member_public_key_file);
    if (0 != ret) {
        return ret;
    }

    // Read group public key from disk
    struct ecdaa_group_public_key_ZZZ gpk;
    ret = ecdaa_group_public_key_ZZZ_deserialize_file(&gpk, group_public_key_file);
    if (0 != ret) {
        return ret;
    }

    // Read credential and credential signature from disk.
    struct ecdaa_credential_ZZZ cred;
    int deserialize_ret = ecdaa_credential_ZZZ_deserialize_with_signature_file(&cred, &pk, &gpk, credential_file, credential_signature_file);
    if (0 != deserialize_ret) {
        return deserialize_ret;
    }

    return SUCCESS;
}
