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

#ifndef ECDAA_CREDENTIAL_ZZZ_H
#define ECDAA_CREDENTIAL_ZZZ_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ecdaa/rand.h>

struct ecdaa_member_public_key_ZZZ;
struct ecdaa_issuer_secret_key_ZZZ;
struct ecdaa_group_public_key_ZZZ;

#include <amcl/ecp_ZZZ.h>
#include <amcl/big_XXX.h>

#include <stdint.h>

/*
 * Credential (provided to Member by Issuer, after successful Join,
 *  and used by Member for signing).
 */
struct ecdaa_credential_ZZZ {
    ECP_ZZZ A;
    ECP_ZZZ B;
    ECP_ZZZ C;
    ECP_ZZZ D;
};

#define ECDAA_CREDENTIAL_ZZZ_LENGTH (4*(2*MODBYTES_XXX + 1))
size_t ecdaa_credential_ZZZ_length(void);

/*
 * Signature over `ecdaa_credential_ZZZ` provided by an Issuer.
 */
struct ecdaa_credential_ZZZ_signature {
    BIG_XXX c;
    BIG_XXX s;
};

#define ECDAA_CREDENTIAL_ZZZ_SIGNATURE_LENGTH (2*MODBYTES_XXX)
size_t ecdaa_credential_ZZZ_signature_length(void);

/*
 * Generate a new `ecdaa_credential_ZZZ`.
 *
 * Used by an Issuer, at the end of a successful Join process.
 */
int ecdaa_credential_ZZZ_generate(struct ecdaa_credential_ZZZ *cred_out,
                                  struct ecdaa_credential_ZZZ_signature *cred_sig_out,
                                  struct ecdaa_issuer_secret_key_ZZZ *isk,
                                  struct ecdaa_member_public_key_ZZZ *member_pk,
                                  ecdaa_rand_func get_random);

/*
 * Validate a credential and its signature.
 *
 * Returns:
 * 0 on success
 * -1 if Join response is invalid
 */
int ecdaa_credential_ZZZ_validate(struct ecdaa_credential_ZZZ *credential,
                                  struct ecdaa_credential_ZZZ_signature *credential_signature,
                                  struct ecdaa_member_public_key_ZZZ *member_pk,
                                  struct ecdaa_group_public_key_ZZZ *gpk);

/*
 * Serialize an `ecdaa_credential_ZZZ`
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
void ecdaa_credential_ZZZ_serialize(uint8_t *buffer_out,
                                     struct ecdaa_credential_ZZZ *credential);


int ecdaa_credential_ZZZ_serialize_file(const char* file,
                                    struct ecdaa_credential_ZZZ *credential);

int ecdaa_credential_ZZZ_serialize_fp(FILE* fp,
                                    struct ecdaa_credential_ZZZ *credential);

/*
 * Serialize an `ecdaa_credential_ZZZ_signature`
 *
 * Serialized format is:
 *  ( c | s )
 *  where all numbers are zero-padded big-endian.
 *
 * The provided buffer is assumed to be large enough.
 */
void ecdaa_credential_ZZZ_signature_serialize(uint8_t *buffer_out,
                                              struct ecdaa_credential_ZZZ_signature *cred_sig);

int ecdaa_credential_ZZZ_signature_serialize_file(const char* file,
                                              struct ecdaa_credential_ZZZ_signature *cred_sig);

int ecdaa_credential_ZZZ_signature_serialize_fp(FILE* fp,
                                              struct ecdaa_credential_ZZZ_signature *cred_sig);
/*
 * De-serialize an `ecdaa_credential_ZZZ` and `ecdaa_credential_ZZZ_signature`,
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
int ecdaa_credential_ZZZ_deserialize_with_signature(struct ecdaa_credential_ZZZ *credential_out,
                                                    struct ecdaa_member_public_key_ZZZ *member_pk,
                                                    struct ecdaa_group_public_key_ZZZ *gpk,
                                                    uint8_t *cred_buffer_in,
                                                    uint8_t *cred_sig_buffer_in);

int ecdaa_credential_ZZZ_deserialize_with_signature_file(struct ecdaa_credential_ZZZ *credential_out,
                                                    struct ecdaa_member_public_key_ZZZ *pk,
                                                    struct ecdaa_group_public_key_ZZZ *gpk,
                                                    const char *credential_file,
                                                    const char *credential_signature_file);

int ecdaa_credential_ZZZ_deserialize_with_signature_fp(struct ecdaa_credential_ZZZ *credential_out,
                                                    struct ecdaa_member_public_key_ZZZ *pk,
                                                    struct ecdaa_group_public_key_ZZZ *gpk,
                                                    FILE *credential_file,
                                                    FILE *credential_signature_file);
/*
 * De-serialize an `ecdaa_credential_ZZZ`, check its validity (signature _not_ checked).
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
int ecdaa_credential_ZZZ_deserialize(struct ecdaa_credential_ZZZ *credential_out,
                                     uint8_t *buffer_in);

int ecdaa_credential_ZZZ_deserialize_file(struct ecdaa_credential_ZZZ *credential_out,
                                     const char* file);

int ecdaa_credential_ZZZ_deserialize_fp(struct ecdaa_credential_ZZZ *credential_out,
                                     FILE* file);

#ifdef __cplusplus
}
#endif

#endif
