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

#ifndef ECDAA_ISSUER_KEYPAIR_ZZZ_H
#define ECDAA_ISSUER_KEYPAIR_ZZZ_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ecdaa/group_public_key_ZZZ.h>
#include <ecdaa/rand.h>

#include <amcl/include/big_XXX.h>

/*
 * Issuer's public key.
 */
struct ecdaa_issuer_public_key_ZZZ {
    struct ecdaa_group_public_key_ZZZ gpk;
    BIG_XXX c;
    BIG_XXX sx;
    BIG_XXX sy;
};

#define ECDAA_ISSUER_PUBLIC_KEY_ZZZ_LENGTH (ECDAA_GROUP_PUBLIC_KEY_ZZZ_LENGTH + MODBYTES_XXX + MODBYTES_XXX + MODBYTES_XXX)
size_t ecdaa_issuer_public_key_ZZZ_length(void);

/*
 * Issuer's secret key.
 */
struct ecdaa_issuer_secret_key_ZZZ {
    BIG_XXX x;
    BIG_XXX y;
};

#define ECDAA_ISSUER_SECRET_KEY_ZZZ_LENGTH (2*MODBYTES_XXX)
size_t ecdaa_issuer_secret_key_ZZZ_length(void);

/*
 * Generate a fresh `ecdaa_issuer_public_key_ZZZ`, `ecdaa_issuer_secret_key_ZZZ` keypair.
 *
 * Returns:
 * 0 on success
 * -1 on error
 */
int ecdaa_issuer_key_pair_ZZZ_generate(struct ecdaa_issuer_public_key_ZZZ *pk_out,
                                       struct ecdaa_issuer_secret_key_ZZZ *sk_out,
                                       ecdaa_rand_func get_random);

/*
 * Check the signature on an `ecdaa_issuer_public_key_ZZZ`.
 *
 * Returns:
 * 0 on success
 * -1 if the signature is invalid
 */
int ecdaa_issuer_public_key_ZZZ_validate(struct ecdaa_issuer_public_key_ZZZ *ipk);

/*
 * Serialize an `ecdaa_issuer_public_key_ZZZ`
 *
 * The serialized format is:
 *  ( gpk | c | sx | sy )
 *  where c, sx, and sy are zero-padded and in big-endian byte-order.
 *  Cf. `group_public_key_ZZZ.h` for the serialization of `gpk`.
 *
 * The provided buffer is assumed to be large enough.
 */
void ecdaa_issuer_public_key_ZZZ_serialize(uint8_t *buffer_out,
                                            struct ecdaa_issuer_public_key_ZZZ *ipk);

int ecdaa_issuer_public_key_ZZZ_serialize_fp(FILE *p,
                                            struct ecdaa_issuer_public_key_ZZZ *ipk);

int ecdaa_issuer_public_key_ZZZ_serialize_file(const char* file,
                                           struct ecdaa_issuer_public_key_ZZZ *ipk);



/*
 * De-serialize an `ecdaa_issuer_public_key_ZZZ` and check its validity and signature.
 *
 * The expected serialized format is:
 *  ( gpk | c | sx | sy )
 *  where c, sx, and sy are zero-padded and in big-endian byte-order.
 *  Cf. `group_public_key_ZZZ.h` for the serialization of `gpk`.
 *
 *  Returns:
 *  0 on success
 *  -1 if gpk is invalid
 *  -1 if format of c, sx, or sy is invalid
 *  -2 if (c, sx, sy) don't verify
 */
int ecdaa_issuer_public_key_ZZZ_deserialize(struct ecdaa_issuer_public_key_ZZZ *ipk_out,
                                             uint8_t *buffer_in);

int ecdaa_issuer_public_key_ZZZ_deserialize_file(struct ecdaa_issuer_public_key_ZZZ *ipk_out,
                                            const char* file);

int ecdaa_issuer_public_key_ZZZ_deserialize_fp(struct ecdaa_issuer_public_key_ZZZ *ipk_out,
                                            FILE* fp);

/*
 * Serialize an `ecdaa_issuer_secret_key_ZZZ`
 *
 * The serialized format is:
 *  ( x | y )
 *  as zero-padded numbers in big-endian byte-order.
 *
 * The provided buffer is assumed to be large enough.
 */
void ecdaa_issuer_secret_key_ZZZ_serialize(uint8_t *buffer_out,
                                           struct ecdaa_issuer_secret_key_ZZZ *isk);

int ecdaa_issuer_secret_key_ZZZ_serialize_file(const char* file, struct ecdaa_issuer_secret_key_ZZZ *isk);

int ecdaa_issuer_secret_key_ZZZ_serialize_fp(FILE* fp, struct ecdaa_issuer_secret_key_ZZZ *isk);



/*
 * De-serialize an `ecdaa_issuer_secret_key_ZZZ`
 *
 * The expected serialized format is:
 *  ( x | y )
 *  as zero-padded numbers in big-endian byte-order.
 *
 *  Returns:
 *  0 on success
 */
int ecdaa_issuer_secret_key_ZZZ_deserialize(struct ecdaa_issuer_secret_key_ZZZ *isk_out,
                                             uint8_t *buffer_in);

int ecdaa_issuer_secret_key_ZZZ_deserialize_file(struct ecdaa_issuer_secret_key_ZZZ *isk_out,
                                            const char* file);

int ecdaa_issuer_secret_key_ZZZ_deserialize_fp(struct ecdaa_issuer_secret_key_ZZZ *isk_out,
                                            FILE* fp);


#ifdef __cplusplus
}
#endif

#endif
