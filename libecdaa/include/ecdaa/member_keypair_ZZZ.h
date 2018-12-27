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

#ifndef ECDAA_MEMBER_KEYPAIR_ZZZ_H
#define ECDAA_MEMBER_KEYPAIR_ZZZ_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ecdaa/rand.h>

#include <amcl/big_XXX.h>
#include <amcl/ecp_ZZZ.h>

/*
 * Member's public key.
 *
 * Only used during a Join process.
 */
struct ecdaa_member_public_key_ZZZ {
    ECP_ZZZ Q;
    BIG_XXX c;
    BIG_XXX s;
    BIG_XXX n;
};

#define ECDAA_MEMBER_PUBLIC_KEY_ZZZ_LENGTH ((2*MODBYTES_XXX + 1) + MODBYTES_XXX + MODBYTES_XXX + MODBYTES_XXX)
size_t ecdaa_member_public_key_ZZZ_length(void);

/*
 * Member's secret key.
 */
struct ecdaa_member_secret_key_ZZZ {
    BIG_XXX sk;
};

#define ECDAA_MEMBER_SECRET_KEY_ZZZ_LENGTH (MODBYTES_XXX)
size_t ecdaa_member_secret_key_ZZZ_length(void);

/*
 * Generate a fresh `ecdaa_member_public_key_ZZZ`, `ecdaa_member_secret_key_ZZZ` pair.
 *
 * Returns:
 * 0 on success
 * -1 on error
 */
int ecdaa_member_key_pair_ZZZ_generate(struct ecdaa_member_public_key_ZZZ *pk_out,
                                       struct ecdaa_member_secret_key_ZZZ *sk_out,
                                       uint8_t *nonce,
                                       uint32_t nonce_length,
                                       ecdaa_rand_func get_random);

/*
 * Check the signature on an `ecdaa_member_public_key_ZZZ`.
 *
 * Returns:
 * 0 on success
 * -1 if signature is not valid.
 */
int ecdaa_member_public_key_ZZZ_validate(struct ecdaa_member_public_key_ZZZ *pk,
                                         uint8_t *nonce_in,
                                         uint32_t nonce_length);

/*
 * Serialize an `ecdaa_member_public_key_ZZZ`
 *
 * The serialized format is:
 *  ( 0x04 | Q.x-coord | Q.y-coord | c | s | n)
 *  where all numbers are zero-padded and in big-endian byte-order.
 *
 * The provided buffer is assumed to be large enough.
 */
void ecdaa_member_public_key_ZZZ_serialize(uint8_t *buffer_out,
                                           struct ecdaa_member_public_key_ZZZ *pk);

int ecdaa_member_public_key_ZZZ_serialize_file(const char* file,
                                           struct ecdaa_member_public_key_ZZZ *pk);

int ecdaa_member_public_key_ZZZ_serialize_fp(FILE* fp,
                                           struct ecdaa_member_public_key_ZZZ *pk);
/*
 * De-serialize an `ecdaa_member_public_key_ZZZ`, and check its validity and signature.
 *
 * The `nonce_in` should be the nonce
 *  provided by the Issuer when the Member generated this public key.
 *
 * The serialized format is expected to be:
 *  ( 0x04 | Q.x-coord | Q.y-coord | c | s | n)
 *  where all numbers are zero-padded and in big-endian byte-order.
 *
 * Returns:
 * 0 on success
 * -1 if the format is incorrect
 * -2 if  (c,s,n) don't verify
 */
int ecdaa_member_public_key_ZZZ_deserialize(struct ecdaa_member_public_key_ZZZ *pk_out,
                                             uint8_t *buffer_in,
                                             uint8_t *nonce_in,
                                             uint32_t nonce_length);

int ecdaa_member_public_key_ZZZ_deserialize_file(struct ecdaa_member_public_key_ZZZ *pk_out,
                                            const char* file,
                                            uint8_t *nonce_in,
                                            uint32_t nonce_length);

int ecdaa_member_public_key_ZZZ_deserialize_fp(struct ecdaa_member_public_key_ZZZ *pk_out,
                                            FILE* file,
                                            uint8_t *nonce_in,
                                            uint32_t nonce_length);

/*
 * De-serialize an `ecdaa_member_public_key_ZZZ`, check its validity, but NOT its signature.
 *
 * The serialized format is expected to be:
 *  ( 0x04 | Q.x-coord | Q.y-coord | c | s | n)
 *  where all numbers are zero-padded and in big-endian byte-order.
 *
 *  NOTE: The full public key (including the signature) is de-serialized,
 *  even though the signature does NOT get checked.
 *
 * Returns:
 * 0 on success
 * -1 if the format is incorrect
 */
int ecdaa_member_public_key_ZZZ_deserialize_no_check(struct ecdaa_member_public_key_ZZZ *pk_out,
                                                     uint8_t *buffer_in);

int ecdaa_member_public_key_ZZZ_deserialize_no_check_file(struct ecdaa_member_public_key_ZZZ *pk_out,
                                                     const char *file);

int ecdaa_member_public_key_ZZZ_deserialize_no_check_fp(struct ecdaa_member_public_key_ZZZ *pk_out,
                                                     FILE *file);

/*
 * Serialize an `ecdaa_member_secret_key_ZZZ`
 *
 * The serialized secret key is zero-padded in big-endian byte-order.
 *
 * The provided buffer is assumed to be large enough.
 */
void ecdaa_member_secret_key_ZZZ_serialize(uint8_t *buffer_out,
                                           struct ecdaa_member_secret_key_ZZZ *sk);

int ecdaa_member_secret_key_ZZZ_serialize_file(const char* file,
                                           struct ecdaa_member_secret_key_ZZZ *sk);

int ecdaa_member_secret_key_ZZZ_serialize_fp(FILE* fp,
                                           struct ecdaa_member_secret_key_ZZZ *sk);
/*
 * De-serialize an `ecdaa_member_secret_key_ZZZ`
 *
 * The serialized secret key is expected to be zero-padded in big-endian byte-order.
 *
 * Returns:
 * 0 on success
 */
int ecdaa_member_secret_key_ZZZ_deserialize(struct ecdaa_member_secret_key_ZZZ *sk_out,
                                            uint8_t *buffer_in);

int ecdaa_member_secret_key_ZZZ_deserialize_file(struct ecdaa_member_secret_key_ZZZ *sk_out,
                                            const char* file);

int ecdaa_member_secret_key_ZZZ_deserialize_fp(struct ecdaa_member_secret_key_ZZZ *sk_out,
                                            FILE* fp);


#ifdef __cplusplus
}
#endif

#endif
