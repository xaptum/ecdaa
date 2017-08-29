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

#ifndef XAPTUM_ECDAA_CREDENTIAL_H
#define XAPTUM_ECDAA_CREDENTIAL_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

struct ecdaa_issuer_t;
struct ecdaa_member_t;
struct ecdaa_member_public_key_t;

#include <amcl/ecp_BN254.h>
#include <amcl/big_256_56.h>
#include <amcl/randapi.h>

/*
 * Credential (provided to Member by Issuer, after successful Join).
 */
typedef struct ecdaa_credential_t {
    ECP_BN254 A;
    ECP_BN254 B;
    ECP_BN254 C;
    ECP_BN254 D;
} ecdaa_credential_t;

/*
 * Signature over `ecdaa_credential_t` provided by an Issuer.
 */
typedef struct ecdaa_credential_signature_t {
    BIG_256_56 c;
    BIG_256_56 s;
} ecdaa_credential_signature_t;

/*
 * Generate a new `ecdaa_credential_t`.
 *
 * Used by an Issuer, at the end of a successful Join process.
 */
int ecdaa_generate_credential(ecdaa_credential_t *cred,
                              ecdaa_credential_signature_t *cred_sig_out,
                              struct ecdaa_issuer_t *issuer,
                              struct ecdaa_member_public_key_t *member_pk);

/*
 * Validate a credential and its signature.
 *
 * Returns:
 * 0 on success
 * -1 if Join response is invalid
 */
int ecdaa_validate_credential(struct ecdaa_credential_t *credential,
                              struct ecdaa_credential_signature_t *credential_signature,
                              struct ecdaa_member_t *member);

/*
 * Serialize an `ecdaa_credential_t`
 *
 * The provided buffer is assumed to be large enough.
 */
void ecdaa_serialize_credential(uint8_t *buffer_out,
                                uint32_t *out_length,
                                ecdaa_credential_t *credential);

/*
 * De-serialize an `ecdaa_signature_t`
 */
void ecdaa_deserialize_credential(ecdaa_credential_t *credential_out,
                                  uint8_t *buffer_in,
                                  uint32_t *in_length);

#ifdef __cplusplus
}
#endif

#endif

