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

#ifndef ECDAA_ISSUER_KEYPAIR_BN254_H
#define ECDAA_ISSUER_KEYPAIR_BN254_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ecdaa/group_public_key_BN254.h>

#include <amcl/big_256_56.h>

struct ecdaa_prng;

/*
 * Issuer's public key.
 */
struct ecdaa_issuer_public_key_BN254 {
    struct ecdaa_group_public_key_BN254 gpk;
    BIG_256_56 c;
    BIG_256_56 sx;
    BIG_256_56 sy;
};

#define ECDAA_ISSUER_PUBLIC_KEY_BN254_LENGTH (ECDAA_GROUP_PUBLIC_KEY_BN254_LENGTH + MODBYTES_256_56 + MODBYTES_256_56 + MODBYTES_256_56)
size_t ecdaa_issuer_public_key_BN254_length(void);

/*
 * Issuer's secret key.
 */
struct ecdaa_issuer_secret_key_BN254 {
    BIG_256_56 x;
    BIG_256_56 y;
};

#define ECDAA_ISSUER_SECRET_KEY_BN254_LENGTH (2*MODBYTES_256_56)
size_t ecdaa_issuer_secret_key_BN254_length(void);

/*
 * Generate a fresh `ecdaa_issuer_public_key_BN254`, `ecdaa_issuer_secret_key_BN254` keypair.
 *
 * Returns:
 * 0 on success
 * -1 on error
 */
int ecdaa_issuer_key_pair_BN254_generate(struct ecdaa_issuer_public_key_BN254 *pk_out,
                                         struct ecdaa_issuer_secret_key_BN254 *sk_out,
                                         struct ecdaa_prng *prng);

/*
 * Check the signature on an `ecdaa_issuer_public_key_BN254`.
 *
 * Returns:
 * 0 on success
 * -1 if the signature is invalid
 */
int ecdaa_issuer_public_key_BN254_validate(struct ecdaa_issuer_public_key_BN254 *ipk);

/*
 * Serialize an `ecdaa_issuer_public_key_BN254`
 *
 * The serialized format is:
 *  ( gpk | c | sx | sy )
 *  where c, sx, and sy are zero-padded and in big-endian byte-order.
 *  Cf. `group_public_key_BN254.h` for the serialization of `gpk`.
 *
 * The provided buffer is assumed to be large enough.
 */
void ecdaa_issuer_public_key_BN254_serialize(uint8_t *buffer_out,
                                             struct ecdaa_issuer_public_key_BN254 *ipk);

/*
 * De-serialize an `ecdaa_issuer_public_key_BN254` and check its validity and signature.
 *
 * The expected serialized format is:
 *  ( gpk | c | sx | sy )
 *  where c, sx, and sy are zero-padded and in big-endian byte-order.
 *  Cf. `group_public_key_BN254.h` for the serialization of `gpk`.
 *
 *  Returns:
 *  0 on success
 *  -1 if gpk is invalid
 *  -1 if format of c, sx, or sy is invalid
 *  -2 if (c, sx, sy) don't verify 
 */
int ecdaa_issuer_public_key_BN254_deserialize(struct ecdaa_issuer_public_key_BN254 *ipk_out,
                                              uint8_t *buffer_in);

/*
 * Serialize an `ecdaa_issuer_secret_key_BN254`
 *
 * The serialized format is:
 *  ( x | y )
 *  as zero-padded numbers in big-endian byte-order.
 *
 * The provided buffer is assumed to be large enough.
 */
void ecdaa_issuer_secret_key_BN254_serialize(uint8_t *buffer_out,
                                             struct ecdaa_issuer_secret_key_BN254 *isk);

/*
 * De-serialize an `ecdaa_issuer_secret_key_BN254`
 *
 * The expected serialized format is:
 *  ( x | y )
 *  as zero-padded numbers in big-endian byte-order.
 *
 *  Returns:
 *  0 on success
 */
int ecdaa_issuer_secret_key_BN254_deserialize(struct ecdaa_issuer_secret_key_BN254 *isk_out,
                                              uint8_t *buffer_in);

#ifdef __cplusplus
}
#endif

#endif

