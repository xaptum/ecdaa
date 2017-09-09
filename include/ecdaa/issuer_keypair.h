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

#ifndef XAPTUM_ECDAA_ISSUER_KEYPAIR_H
#define XAPTUM_ECDAA_ISSUER_KEYPAIR_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ecdaa/group_public_key.h>

#include <amcl/big_256_56.h>
#include <amcl/randapi.h>

/*
 * Issuer's public key.
 */
typedef struct ecdaa_issuer_public_key_t {
    ecdaa_group_public_key_t gpk;
    BIG_256_56 c;
    BIG_256_56 sx;
    BIG_256_56 sy;
} ecdaa_issuer_public_key_t;

#define SERIALIZED_ISSUER_PUBLIC_KEY_LENGTH (SERIALIZED_GROUP_PUBLIC_KEY_LENGTH + MODBYTES_256_56 + MODBYTES_256_56 + MODBYTES_256_56)
size_t serialized_issuer_public_key_length(void);

/*
 * Issuer's secret key.
 */
typedef struct ecdaa_issuer_secret_key_t {
    BIG_256_56 x;
    BIG_256_56 y;
} ecdaa_issuer_secret_key_t;

#define SERIALIZED_ISSUER_SECRET_KEY_LENGTH (2*MODBYTES_256_56)
size_t serialized_issuer_secret_key_length();

/*
 * Generate a fresh keypair.
 */
int ecdaa_generate_issuer_key_pair(ecdaa_issuer_public_key_t *pk,
                                   ecdaa_issuer_secret_key_t *sk,
                                   csprng *rng);

/*
 * Check the signature on an `ecdaa_issuer_public_key_t`.
 *
 * Returns:
 * 0 on success
 * -1 if the signature is invalid
 */
int ecdaa_validate_issuer_public_key(ecdaa_issuer_public_key_t *ipk);

/*
 * Serialize an `ecdaa_issuer_public_key_t`
 *
 * The serialized format is:
 *  ( gpk | c | sx | sy )
 *  where c, sx, and sy are zero-padded and in big-endian byte-order.
 *  Cf. `group_public_key.h` for the serialization of `gpk`.
 *
 * The provided buffer is assumed to be large enough.
 */
void ecdaa_serialize_issuer_public_key(uint8_t *buffer_out,
                                       ecdaa_issuer_public_key_t *ipk);

/*
 * De-serialize an `ecdaa_issuer_public_key_t` and check its validity and signature.
 *
 * The expected serialized format is:
 *  ( gpk | c | sx | sy )
 *  where c, sx, and sy are zero-padded and in big-endian byte-order.
 *  Cf. `group_public_key.h` for the serialization of `gpk`.
 *
 *  Returns:
 *  0 on success
 *  -1 if gpk is invalid
 *  -1 if format of c, sx, or sy is invalid
 *  -2 if (c, sx, sy) don't verify 
 */
int ecdaa_deserialize_issuer_public_key(ecdaa_issuer_public_key_t *ipk_out,
                                        uint8_t *buffer_in);

/*
 * Serialize an `ecdaa_issuer_secret_key_t`
 *
 * The serialized format is:
 *  ( x | y )
 *  as zero-padded numbers in big-endian byte-order.
 *
 * The provided buffer is assumed to be large enough.
 */
void ecdaa_serialize_issuer_secret_key(uint8_t *buffer_out,
                                       ecdaa_issuer_secret_key_t *isk);

/*
 * De-serialize an `ecdaa_issuer_secret_key_t`
 *
 * The expected serialized format is:
 *  ( x | y )
 *  as zero-padded numbers in big-endian byte-order.
 *
 *  Returns:
 *  0 on success
 */
int ecdaa_deserialize_issuer_secret_key(ecdaa_issuer_secret_key_t *isk_out,
                                        uint8_t *buffer_in);

#ifdef __cplusplus
}
#endif

#endif

