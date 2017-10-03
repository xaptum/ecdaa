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

#ifndef ECDAA_SCHNORR_H
#define ECDAA_SCHNORR_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

struct ecdaa_prng;

#include <amcl/big_XXX.h>
#include <amcl/ecp_ZZZ.h>
#include <amcl/ecp2_ZZZ.h>

#include <stdint.h>

/*
 * Generate a Schnorr public/private keypair.
 *
 * private_key = RAND(Z_p)
 * public_key = private_key * group_generator
 */
void schnorr_keygen_ZZZ(ECP_ZZZ *public_out,
                        BIG_XXX *private_out,
                        struct ecdaa_prng *prng);

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
int schnorr_sign_ZZZ(BIG_XXX *c_out,
                     BIG_XXX *s_out,
                     const uint8_t *msg_in,
                     uint32_t msg_len,
                     ECP_ZZZ *basepoint,
                     ECP_ZZZ *public_key,
                     BIG_XXX private_key,
                     struct ecdaa_prng *prng);

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
int schnorr_verify_ZZZ(BIG_XXX c,
                       BIG_XXX s,
                       const uint8_t *msg_in,
                       uint32_t msg_len,
                       ECP_ZZZ *basepoint,
                       ECP_ZZZ *public_key);

/*
 * Perform an 'credential-Schnorr' signature, used by an Issuer when signing credentials.
 *
 * c_out = Hash ( r*generator | r*member_public_key | generator | B | member_public_key | D ),
 * s_out = s = r + c_out * private_key,
 *  where r = RAND(Z_p),
 *  B and D are the corresponding values of an `ecdaa_credential`,
 *  public_key is the requesting Member's public key,
 *
 * c_out and s_out will be reduced modulo the group order (and thus normalized) upon return
 *
 *  Returns:
 *   0 on success
 */
int credential_schnorr_sign_ZZZ(BIG_XXX *c_out,
                                BIG_XXX *s_out,
                                ECP_ZZZ *B,
                                ECP_ZZZ *member_public_key,
                                ECP_ZZZ *D,
                                BIG_XXX issuer_private_key_y,
                                BIG_XXX credential_random,
                                struct ecdaa_prng *prng);

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
int credential_schnorr_verify_ZZZ(BIG_XXX c,
                                  BIG_XXX s,
                                  ECP_ZZZ *B,
                                  ECP_ZZZ *member_public_key,
                                  ECP_ZZZ *D);

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
int issuer_schnorr_sign_ZZZ(BIG_XXX *c_out,
                            BIG_XXX *sx_out,
                            BIG_XXX *sy_out,
                            ECP2_ZZZ *X,
                            ECP2_ZZZ *Y,
                            BIG_XXX issuer_private_key_x,
                            BIG_XXX issuer_private_key_y,
                            struct ecdaa_prng *prng);

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
int issuer_schnorr_verify_ZZZ(BIG_XXX c,
                              BIG_XXX sx,
                              BIG_XXX sy,
                              ECP2_ZZZ *X,
                              ECP2_ZZZ *Y);

#ifdef __cplusplus
}
#endif

#endif
