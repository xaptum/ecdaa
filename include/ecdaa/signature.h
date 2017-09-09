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

/*
 * Serialize an `ecdaa_signature_t`
 *
 * The provided buffer is assumed to be large enough.
 */
void ecdaa_serialize_signature(uint8_t *buffer_out,
                               uint32_t *out_length,
                               ecdaa_signature_t *signature);

/*
 * De-serialize an `ecdaa_signature_t`
 */
void ecdaa_deserialize_signature(ecdaa_signature_t *signature_out,
                                 uint8_t *buffer_in,
                                 uint32_t *in_length);

#ifdef __cplusplus
}
#endif

#endif
