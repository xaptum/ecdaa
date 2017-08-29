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

#ifdef __cplusplus
extern "C" {
#endif

#include <amcl/big_256_56.h>
#include <amcl/ecp_BN254.h>
#include <amcl/ecp2_BN254.h>
#include <amcl/randapi.h>

#include <stdint.h>

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
 * De-serialize a Schnorr public key.
 *
 * Serialized format is expected to be
 *  [0x4 | x-coord | y-coord]
 *  where coordinates are in big-endian byte-order.
 *
 * Returns:
 * 0 on success
 * -1 if public_key is not valid
 */
int convert_schnorr_public_key_from_bytes(const octet *public_key_as_bytes, ECP_BN254 *public_key);

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
                 const uint8_t *msg_in,
                 uint32_t msg_len,
                 ECP_BN254 *basepoint,
                 ECP_BN254 *public_key,
                 BIG_256_56 private_key,
                 csprng *rng);

/*
 * Verify that (c, s) is a valid Schnorr signature of msg_in, allowing for a non-standard basepoint.
 *
 * Check c = Hash( s*basepoint - c*public_key | basepoint | public_key | msg_in )
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
                   const uint8_t *msg_in,
                   uint32_t msg_len,
                   ECP_BN254 *basepoint,
                   ECP_BN254 *public_key);

/*
 * Perform an 'credential-Schnorr' signature, used by an Issuer when signing credentials.
 *
 * c_out = Hash ( r*generator | r*member_public_key | generator | B | member_public_key | D ),
 * s_out = s = r + c_out * private_key,
 *  where r = RAND(Z_p),
 *  B and D are the corresponding values of an `ecdaa_credential_t`,
 *  public_key is the requesting Member's public key,
 *
 * c_out and s_out will be reduced modulo the group order (and thus normalized) upon return
 *
 *  Returns:
 *   0 on success
 */
int credential_schnorr_sign(BIG_256_56 *c_out,
                            BIG_256_56 *s_out,
                            ECP_BN254 *B,
                            ECP_BN254 *member_public_key,
                            ECP_BN254 *D,
                            BIG_256_56 issuer_private_key_y,
                            BIG_256_56 credential_random,
                            csprng *rng);

/*
 * Verify that (c, s) is a valid 'credential-Schnorr' signature.
 *
 * Check c = Hash( s*generator - c*B | s*public_key - c*D | generator | B | member_public_key | D ),
 *
 * c and s must be reduced modulo group order (and thus normalized, too), first
 *
 * NOTE: Because this is used as part of a verification process,
 * THE VALIDITY OF B, member_public_key, AND D ARE NOT CHECKED.
 *
 * Returns:
 *  0 on success
 *  -1 if (c, s) is not a valid signature
 */
int credential_schnorr_verify(BIG_256_56 c,
                              BIG_256_56 s,
                              ECP_BN254 *B,
                              ECP_BN254 *member_public_key,
                              ECP_BN254 *D);

/*
 * Perform an 'issuer-Schnorr' signature, used by an Issuer when creating its own key-pair.
 *
 * c_out = Hash ( rx*generator_2 | ry*generator_2 | generator_2 | X | Y ),
 * sx_out = rx + c_out * private_key_x,
 * sy_out = ry + c_out * private_key_y,
 *  where rx = RAND(Z_p),
 *  ry = RAND(Z_p),
 *  X, Y is the issuer's public key,
 *  private_key_x, private_key_y is the issuer's private key.
 *
 * c_out, sx_out, and sy_out will be reduced modulo the group order (and thus normalized) upon return
 *
 *  Returns:
 *   0 on success
 */
int issuer_schnorr_sign(BIG_256_56 *c_out,
                        BIG_256_56 *sx_out,
                        BIG_256_56 *sy_out,
                        ECP2_BN254 *X,
                        ECP2_BN254 *Y,
                        BIG_256_56 issuer_private_key_x,
                        BIG_256_56 issuer_private_key_y,
                        csprng *rng);

/*
 * Verify that (c, sx, sy) is a valid 'issuer-Schnorr' signature.
 *
 * Check c = Hash( sx*generator_2 - c*X | sy*generator_2 - c*Y | generator_2 | X | Y ),
 *
 * c and s must be reduced modulo group order (and thus normalized, too), first
 *
 * NOTE: Because this is used as part of a verification process,
 * THE VALIDITY OF X, AND Y ARE NOT CHECKED.
 *
 * Returns:
 *  0 on success
 *  -1 if (c, s) is not a valid signature
 */
int issuer_schnorr_verify(BIG_256_56 c,
                          BIG_256_56 sx,
                          BIG_256_56 sy,
                          ECP2_BN254 *X,
                          ECP2_BN254 *Y);

#ifdef __cplusplus
}
#endif

#endif
