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

#ifndef XAPTUM_ECDAA_SCHNORR_H
#define XAPTUM_ECDAA_SCHNORR_H
#pragma once

#include <amcl/big_256_56.h>
#include <amcl/ecp_BN254.h>
#include <amcl/randapi.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Generate a Schnorr public/private keypair.
 *
 * private_key = RAND(Z_p)
 * public_key = private_key * group_generator
 */
void schnorr_keygen(ECP_BN254 *public_out,
                    BIG_256_56 *private_out,
                    csprng *rng);

/*
 * Check if the given EC point is a member of the group.
 *
 * Returns:
 * 0 on success
 * -1 if the point is _not_ in the group
 */
int check_point_membership(ECP_BN254 *point);

/*
 * De-serialize a Schnorr public key, and check it for validity.
 *
 * Serialized format is expected to be
 *  [0x4 | x-coord | y-coord]
 *  where coordinates are in big-endian byte-order.
 *
 * Returns:
 * 0 on success
 * -1 if public_key is not valid
 */
int convert_schnorr_public_key_from_bytes(octet *public_key_as_bytes, ECP_BN254 *public_key);

/*
 * Serialize a Schnorr public key.
 *
 * Serialized format is
 *  [0x4 | x-coord | y-coord]
 *  where coordinates are in big-endian byte-order.
 */
void convert_schnorr_public_key_to_bytes(octet *public_key_as_bytes, ECP_BN254 *public_key);

/*
 * Perform Schnorr signature of msg_in, allowing for a non-standard basepoint.
 *
 * c_out = Hash ( RAND(Z_p)*basepoint | basepoint | public_key | msg_in )
 * s_out = s = RAND(Z_p) + c_out * private_key
 *
 * public_key = private_key * basepoint
 *
 * c_out and s_out will be reduced modulo the group order (and thus normalized) upon return
 *
 *  Returns:
 *   0 on success
 *   -1 if basepoint is not valid
 */
int schnorr_sign(BIG_256_56 *c_out,
                 BIG_256_56 *s_out,
                 uint8_t *msg_in,
                 uint32_t msg_len,
                 ECP_BN254 *basepoint,
                 ECP_BN254 *public_key,
                 BIG_256_56 private_key,
                 csprng *rng);

/*
 * Verify that (c, s) is a valid Schnorr signature of msg_in, allowing for a non-standard basepoint.
 *
 * Check c = Hash( s*basepoint - c*public_key | basepoint | public_key | msg_in )
 * NOTE: Assumes public key has already been checked for validity!
 *
 * c and s must be reduced modulo group order (and thus normalized, too), first
 *
 * public_key = some_private_key * basepoint
 *
 * Returns:
 *  0 on success
 *  -1 if (c, s) is not a valid signature
 */
int schnorr_verify(BIG_256_56 c,
                   BIG_256_56 s,
                   uint8_t *msg_in,
                   uint32_t msg_len,
                   ECP_BN254 *basepoint,
                   ECP_BN254 *public_key);

#ifdef __cplusplus
}
#endif

#endif
