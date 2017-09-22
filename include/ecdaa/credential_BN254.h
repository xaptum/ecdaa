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

#ifndef ECDAA_CREDENTIAL_BN254_H
#define ECDAA_CREDENTIAL_BN254_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

struct ecdaa_member_public_key_BN254;
struct ecdaa_issuer_secret_key_BN254;
struct ecdaa_group_public_key_BN254;
struct ecdaa_prng;

#include <amcl/ecp_BN254.h>
#include <amcl/big_256_56.h>

#include <stdint.h>

/*
 * Credential (provided to Member by Issuer, after successful Join,
 *  and used by Member for signing).
 */
struct ecdaa_credential_BN254 {
    ECP_BN254 A;
    ECP_BN254 B;
    ECP_BN254 C;
    ECP_BN254 D;
};

#define ECDAA_CREDENTIAL_BN254_LENGTH (4*(2*MODBYTES_256_56 + 1))
size_t ecdaa_credential_BN254_length(void);

/*
 * Signature over `ecdaa_credential_BN254` provided by an Issuer.
 */
struct ecdaa_credential_BN254_signature {
    BIG_256_56 c;
    BIG_256_56 s;
};

#define ECDAA_CREDENTIAL_BN254_SIGNATURE_LENGTH (2*MODBYTES_256_56)
size_t ecdaa_credential_BN254_signature_length(void);

/*
 * Generate a new `ecdaa_credential_BN254`.
 *
 * Used by an Issuer, at the end of a successful Join process.
 */
int ecdaa_credential_BN254_generate(struct ecdaa_credential_BN254 *cred_out,
                                    struct ecdaa_credential_BN254_signature *cred_sig_out,
                                    struct ecdaa_issuer_secret_key_BN254 *isk,
                                    struct ecdaa_member_public_key_BN254 *member_pk,
                                    struct ecdaa_prng *prng);

/*
 * Validate a credential and its signature.
 *
 * Returns:
 * 0 on success
 * -1 if Join response is invalid
 */
int ecdaa_credential_BN254_validate(struct ecdaa_credential_BN254 *credential,
                                    struct ecdaa_credential_BN254_signature *credential_signature,
                                    struct ecdaa_member_public_key_BN254 *member_pk,
                                    struct ecdaa_group_public_key_BN254 *gpk);

/*
 * Serialize an `ecdaa_credential_BN254`
 *
 * Serialized format is;
 *  ( 0x04 | A.x-coord | A.y-coord |
 *      0x04 | B.x-coord | B.y-coord |
 *      0x04 | C.x-coord | C.y-coord |
 *      0x04 | D.x-coord | D.y-coord )
 *  where all numbers are zero-padded big-endian.
 *
 * The provided buffer is assumed to be large enough.
 */
void ecdaa_credential_BN254_serialize(uint8_t *buffer_out,
                                      struct ecdaa_credential_BN254 *credential);

/*
 * Serialize an `ecdaa_credential_BN254_signature`
 *
 * Serialized format is:
 *  ( c | s )
 *  where all numbers are zero-padded big-endian.
 *
 * The provided buffer is assumed to be large enough.
 */
void ecdaa_credential_BN254_signature_serialize(uint8_t *buffer_out,
                                                struct ecdaa_credential_BN254_signature *cred_sig);

/*
 * De-serialize an `ecdaa_credential_BN254` and `ecdaa_credential_BN254_signature`,
 *  and check both validity _and_ signature.
 *
 * Expected serialized format is;
 *  ( 0x04 | A.x-coord | A.y-coord |
 *      0x04 | B.x-coord | B.y-coord |
 *      0x04 | C.x-coord | C.y-coord |
 *      0x04 | D.x-coord | D.y-coord |
 *      c |
 *      s )
 *  where all numbers are zero-padded big-endian.
 *
 *  Returns:
 *  0 on success
 *  -1 if credential is mal-formed
 *  -2 if signature is invalid
 */
int ecdaa_credential_BN254_deserialize_with_signature(struct ecdaa_credential_BN254 *credential_out,
                                                      struct ecdaa_member_public_key_BN254 *member_pk,
                                                      struct ecdaa_group_public_key_BN254 *gpk,
                                                      uint8_t *buffer_in);

/*
 * De-serialize an `ecdaa_credential_BN254`, check its validity (signature _not_ checked).
 *
 * Expected serialized format is;
 *  ( 0x04 | A.x-coord | A.y-coord |
 *      0x04 | B.x-coord | B.y-coord |
 *      0x04 | C.x-coord | C.y-coord |
 *      0x04 | D.x-coord | D.y-coord )
 *  where all numbers are zero-padded big-endian.
 *
 * Returns:
 * 0 on success
 * -1 if credential is mal-formed
 */
int ecdaa_credential_BN254_deserialize(struct ecdaa_credential_BN254 *credential_out,
                                       uint8_t *buffer_in);

#ifdef __cplusplus
}
#endif

#endif

