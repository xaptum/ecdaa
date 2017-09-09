/******************************************************************************
 *
 * Copyright 2017 Xaptum, Inc.
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

#ifndef XAPTUM_ECDAA_SIGNATURE_H
#define XAPTUM_ECDAA_SIGNATURE_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <amcl/big_256_56.h>
#include <amcl/ecp_BN254.h>

/*
 * ECDAA signature.
 */
typedef struct ecdaa_signature_t {
    BIG_256_56 c;
    BIG_256_56 s;
    ECP_BN254 R;
    ECP_BN254 S;
    ECP_BN254 T;
    ECP_BN254 W;
} ecdaa_signature_t;

#define SERIALIZED_SIGNATURE_LENGTH (2*MODBYTES_256_56 + 4*(2*MODBYTES_256_56 + 1))
size_t serialized_signature_length();

/*
 * Serialize an `ecdaa_signature_t`
 *
 * The serialized format is:
 *  ( c | s |
 *    0x04 | R.x-coord | R.y-coord |
 *    0x04 | S.x-coord | S.y-coord |
 *    0x04 | T.x-coord | T.y-coord |
 *    0x04 | W.x-coord | W.y-coord )
 *
 * The provided buffer is assumed to be large enough.
 */
void ecdaa_serialize_signature(uint8_t *buffer_out,
                               ecdaa_signature_t *signature);

/*
 * De-serialize an `ecdaa_signature_t`
 *
 * The serialized format is:
 *  ( c | s |
 *    0x04 | R.x-coord | R.y-coord |
 *    0x04 | S.x-coord | S.y-coord |
 *    0x04 | T.x-coord | T.y-coord |
 *    0x04 | W.x-coord | W.y-coord )
 *
 *  NOTE: The four G1 points are checked as being on the curve,
 *      but not for membership in the group.
 *
 * Returns:
 * 0 on success
 * -1 if signature is mal-formed
 */
int ecdaa_deserialize_signature(ecdaa_signature_t *signature_out,
                                uint8_t *buffer_in);

#ifdef __cplusplus
}
#endif

#endif
