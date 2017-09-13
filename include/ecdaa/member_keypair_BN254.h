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

#ifndef ECDAA_MEMBER_KEYPAIR_BN254_H
#define ECDAA_MEMBER_KEYPAIR_BN254_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <amcl/big_256_56.h>
#include <amcl/ecp_BN254.h>

/*
 * Member's public key.
 *
 * Only used during a Join process.
 */
struct ecdaa_member_public_key_BN254 {
    ECP_BN254 Q;
    BIG_256_56 c;
    BIG_256_56 s;
};

#define ECDAA_MEMBER_PUBLIC_KEY_BN254_LENGTH ((2*MODBYTES_256_56 + 1) + MODBYTES_256_56 + MODBYTES_256_56)
size_t ecdaa_member_public_key_BN254_length();

/*
 * Member's secret key.
 */
struct ecdaa_member_secret_key_BN254 {
    BIG_256_56 sk;
};

#define ECDAA_MEMBER_SECRET_KEY_BN254_LENGTH (MODBYTES_256_56)
size_t ecdaa_member_secret_key_BN254_length();

/*
 * Generate a fresh `ecdaa_member_public_key_BN254`, `ecdaa_member_secret_key_BN254` pair.
 *
 * Returns:
 * 0 on success
 * -1 on error
 */
int ecdaa_member_key_pair_BN254_generate(struct ecdaa_member_public_key_BN254 *pk_out,
                                         struct ecdaa_member_secret_key_BN254 *sk_out,
                                         uint8_t *nonce,
                                         uint32_t nonce_length,
                                         csprng *rng);

/*
 * Check the signature on an `ecdaa_member_public_key_BN254`.
 * 
 * Returns:
 * 0 on success
 * -1 if signature is not valid.
 */
int ecdaa_member_public_key_BN254_validate(struct ecdaa_member_public_key_BN254 *pk,
                                           uint8_t *nonce_in,
                                           uint32_t nonce_length);

/*
 * Serialize an `ecdaa_member_public_key_BN254`
 *
 * The serialized format is:
 *  ( 0x04 | Q.x-coord | Q.y-coord | c | s )
 *  where all numbers are zero-padded and in big-endian byte-order.
 *
 * The provided buffer is assumed to be large enough.
 */
void ecdaa_member_public_key_BN254_serialize(uint8_t *buffer_out,
                                             struct ecdaa_member_public_key_BN254 *pk);

/*
 * De-serialize an `ecdaa_member_public_key_BN254`, and check its validity and signature.
 *
 * The `nonce_in` should be the nonce
 *  provided by the Issuer when the Member generated this public key.
 *
 * The serialized format is expected to be:
 *  ( 0x04 | Q.x-coord | Q.y-coord | c | s )
 *  where all numbers are zero-padded and in big-endian byte-order.
 *
 * Returns:
 * 0 on success
 * -1 if the format is incorrect
 * -2 if  (c,s) don't verify
 */
int ecdaa_member_public_key_BN254_deserialize(struct ecdaa_member_public_key_BN254 *pk_out,
                                              uint8_t *buffer_in,
                                              uint8_t *nonce_in,
                                              uint32_t nonce_length);

/*
 * Serialize an `ecdaa_member_secret_key_BN254`
 *
 * The serialized secret key is zero-padded in big-endian byte-order.
 *
 * The provided buffer is assumed to be large enough.
 */
void ecdaa_member_secret_key_BN254_serialize(uint8_t *buffer_out,
                                             struct ecdaa_member_secret_key_BN254 *sk);

/*
 * De-serialize an `ecdaa_member_secret_key_BN254`
 *
 * The serialized secret key is expected to be zero-padded in big-endian byte-order.
 *
 * Returns:
 * 0 on success
 */
int ecdaa_member_secret_key_BN254_deserialize(struct ecdaa_member_secret_key_BN254 *sk_out,
                                              uint8_t *buffer_in);

#ifdef __cplusplus
}
#endif

#endif

