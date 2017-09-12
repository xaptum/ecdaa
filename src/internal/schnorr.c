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

#include "schnorr.h"

#include "explicit_bzero.h"
#include "../amcl-extensions/big_256_56.h"
#include "../amcl-extensions/ecp_BN254.h"
#include "../amcl-extensions/ecp2_BN254.h"

#include <amcl/ecp_BN254.h>
#include <amcl/amcl.h>

#include <assert.h>

void schnorr_keygen(ECP_BN254 *public_out,
                    BIG_256_56 *private_out,
                    csprng *rng)
{
    big_256_56_random_mod_order(private_out, rng);

    ecp_BN254_set_to_generator(public_out);

    ECP_BN254_mul(public_out, *private_out);
}

void convert_schnorr_public_key_to_bytes(octet *public_key_as_bytes, ECP_BN254 *public_key)
{
    BIG_256_56 Q_x, Q_y;
    ECP_BN254_get(Q_x, Q_y, public_key);

    public_key_as_bytes->val[0] = 0x04;
    BIG_256_56_toBytes(&(public_key_as_bytes->val[1]), Q_x);

    BIG_256_56_toBytes(&(public_key_as_bytes->val[MODBYTES_256_56+1]), Q_y);
}

int schnorr_sign(BIG_256_56 *c_out,
                 BIG_256_56 *s_out,
                 const uint8_t *msg_in,
                 uint32_t msg_len,
                 ECP_BN254 *basepoint,
                 ECP_BN254 *public_key,
                 BIG_256_56 private_key,
                 csprng *rng)
{
    // 1) (Commit 1) Verify basepoint belongs to group
    if (0 != ecp_BN254_check_membership(basepoint))
        return -1;

    // 2) (Commit 2) Choose random k <- Z_n
    BIG_256_56 k;
    big_256_56_random_mod_order(&k, rng);

    // 3) (Commit 3) Multiply basepoint by k: R = k*basepoint
    ECP_BN254 R;
    ECP_BN254_copy(&R, basepoint);
    ECP_BN254_mul(&R, k);

    // 4) (Sign 1) Compute c = Hash( R | basepoint | public_key | msg_in )
    uint8_t hash_input_begin[195];
    assert(3*ECP_BN254_LENGTH == sizeof(hash_input_begin));
    ecp_BN254_serialize(hash_input_begin, &R);
    ecp_BN254_serialize(hash_input_begin+ECP_BN254_LENGTH, basepoint);
    ecp_BN254_serialize(hash_input_begin+2*ECP_BN254_LENGTH, public_key);
    big_256_56_from_two_message_hash(c_out, hash_input_begin, sizeof(hash_input_begin), msg_in, msg_len);

    // 5) (Sign 2) Compute s = k + c * private_key
    BIG_256_56 curve_order;
    BIG_256_56_rcopy(curve_order, CURVE_Order_BN254);
    big_256_56_mod_mul_and_add(s_out, k, *c_out, private_key, curve_order);    // normalizes and mod-reduces s_out and c_out

    // Clear intermediate, sensitive memory.
    explicit_bzero(&k, sizeof(BIG_256_56));

    return 0;
}

int schnorr_verify(BIG_256_56 c,
                   BIG_256_56 s,
                   const uint8_t *msg_in,
                   uint32_t msg_len,
                   ECP_BN254 *basepoint,
                   ECP_BN254 *public_key)
{
    int ret = 0;

    // 1) Check public key for validity
    if (0 != ecp_BN254_check_membership(public_key))
        ret = -1;

    // 2) Multiply basepoint by s (R = s*P)
    ECP_BN254 R;
    ECP_BN254_copy(&R, basepoint);
    ECP_BN254_mul(&R, s);

    // 3) Multiply public_key by c (Q_c = c *public_key)
    ECP_BN254 Q_c;
    ECP_BN254_copy(&Q_c, public_key);
    ECP_BN254_mul(&Q_c, c);

    // 4) Compute difference of R and c*Q, and save to R (R = s*P - c*public_key)
    ECP_BN254_sub(&R, &Q_c);
    // Nb. No need to call ECP_BN254_affine here,
    // as R gets passed to ECP_BN254_toOctet in a minute (which implicitly converts to affine)

    // 5) Compute c' = Hash( R | basepoint | msg_in )
    //      (modular-reduce c', too).
    uint8_t hash_input_begin[195];
    assert(3*ECP_BN254_LENGTH == sizeof(hash_input_begin));
    ecp_BN254_serialize(hash_input_begin, &R);
    ecp_BN254_serialize(hash_input_begin+ECP_BN254_LENGTH, basepoint);
    ecp_BN254_serialize(hash_input_begin+2*ECP_BN254_LENGTH, public_key);
    BIG_256_56 c_prime;
    big_256_56_from_two_message_hash(&c_prime, hash_input_begin, sizeof(hash_input_begin), msg_in, msg_len);
    BIG_256_56 curve_order;
    BIG_256_56_rcopy(curve_order, CURVE_Order_BN254);
    BIG_256_56_mod(c_prime, curve_order);

    // 6) Compare c' and c
    if (0 != BIG_256_56_comp(c_prime, c)) {
        ret = -1;
    }

    return ret;
}

int credential_schnorr_sign(BIG_256_56 *c_out,
                            BIG_256_56 *s_out,
                            ECP_BN254 *B,
                            ECP_BN254 *member_public_key,
                            ECP_BN254 *D,
                            BIG_256_56 issuer_private_key_y,
                            BIG_256_56 credential_random,
                            csprng *rng)
{
    // 1) Set generator
    ECP_BN254 generator;
    ecp_BN254_set_to_generator(&generator);

    // 2) Choose random r <- Z_n
    BIG_256_56 r;
    big_256_56_random_mod_order(&r, rng);

    // 3) Multiply generator by r: U = r*generator
    ECP_BN254 U;
    ECP_BN254_copy(&U, &generator);
    ECP_BN254_mul(&U, r);

    // 4) Multiply member_public_key by r: V = r*member_public_key
    ECP_BN254 V;
    ECP_BN254_copy(&V, member_public_key);
    ECP_BN254_mul(&V, r);

    // 5) Compute c = Hash( U | V | generator | B | member_public_key | D )
    uint8_t hash_input[390];
    assert(6*ECP_BN254_LENGTH == sizeof(hash_input));
    ecp_BN254_serialize(hash_input, &U);
    ecp_BN254_serialize(hash_input+ECP_BN254_LENGTH, &V);
    ecp_BN254_serialize(hash_input+2*ECP_BN254_LENGTH, &generator);
    ecp_BN254_serialize(hash_input+3*ECP_BN254_LENGTH, B);
    ecp_BN254_serialize(hash_input+4*ECP_BN254_LENGTH, member_public_key);
    ecp_BN254_serialize(hash_input+5*ECP_BN254_LENGTH, D);
    big_256_56_from_hash(c_out, hash_input, sizeof(hash_input));

    // 6) Compute ly = (credential_random x issuer_private_key_y) mod curve_order
    BIG_256_56 curve_order;
    BIG_256_56_rcopy(curve_order, CURVE_Order_BN254);
    BIG_256_56 ly;
    BIG_256_56_modmul(ly, credential_random, issuer_private_key_y, curve_order);

    // 7) Compute s = r + c * ly
    big_256_56_mod_mul_and_add(s_out, r, *c_out, ly, curve_order);    // normalizes and mod-reduces s_out and c_out

    // Clear intermediate, sensitive memory.
    explicit_bzero(&r, sizeof(BIG_256_56));

    return 0;
}

int credential_schnorr_verify(BIG_256_56 c,
                              BIG_256_56 s,
                              ECP_BN254 *B,
                              ECP_BN254 *member_public_key,
                              ECP_BN254 *D)
{
    int ret = 0;

    // 1) Set generator
    ECP_BN254 generator;
    ecp_BN254_set_to_generator(&generator);

    // 2) Multiply generator by s (R1 = s*P)
    ECP_BN254 R1;
    ECP_BN254_copy(&R1, &generator);
    ECP_BN254_mul(&R1, s);

    // 3) Multiply B by c (B_c = c*B)
    ECP_BN254 B_c;
    ECP_BN254_copy(&B_c, B);
    ECP_BN254_mul(&B_c, c);

    // 4) Compute difference of R1 and c*B, and save to R1 (R1 = s*P - c*B)
    ECP_BN254_sub(&R1, &B_c);
    // Nb. No need to call ECP_BN254_affine here,
    // as R1 gets passed to ECP_BN254_toOctet in a minute (which implicitly converts to affine)

    // 5) Multiply member_public_key by s (R2 = s*member_public_key)
    ECP_BN254 R2;
    ECP_BN254_copy(&R2, member_public_key);
    ECP_BN254_mul(&R2, s);

    // 6) Multiply D by c (D_c = c*D)
    ECP_BN254 D_c;
    ECP_BN254_copy(&D_c, D);
    ECP_BN254_mul(&D_c, c);

    // 7) Compute difference of R2 and c*D, and save to R2 (R2 = s*member_public_key - c*D)
    ECP_BN254_sub(&R2, &D_c);
    // Nb. No need to call ECP_BN254_affine here,
    // as R1 gets passed to ECP_BN254_toOctet in a minute (which implicitly converts to affine)

    // 8) Compute c' = Hash( R1 | R2 | generator | B | member_public_key | D )
    //      (modular-reduce c', too).
    uint8_t hash_input[390];
    assert(6*ECP_BN254_LENGTH == sizeof(hash_input));
    ecp_BN254_serialize(hash_input, &R1);
    ecp_BN254_serialize(hash_input+ECP_BN254_LENGTH, &R2);
    ecp_BN254_serialize(hash_input+2*ECP_BN254_LENGTH, &generator);
    ecp_BN254_serialize(hash_input+3*ECP_BN254_LENGTH, B);
    ecp_BN254_serialize(hash_input+4*ECP_BN254_LENGTH, member_public_key);
    ecp_BN254_serialize(hash_input+5*ECP_BN254_LENGTH, D);
    BIG_256_56 c_prime;
    big_256_56_from_hash(&c_prime, hash_input, sizeof(hash_input));
    BIG_256_56 curve_order;
    BIG_256_56_rcopy(curve_order, CURVE_Order_BN254);
    BIG_256_56_mod(c_prime, curve_order);

    // 6) Compare c' and c
    if (0 != BIG_256_56_comp(c_prime, c)) {
        ret = -1;
    }

    return ret;
}

int issuer_schnorr_sign(BIG_256_56 *c_out,
                        BIG_256_56 *sx_out,
                        BIG_256_56 *sy_out,
                        ECP2_BN254 *X,
                        ECP2_BN254 *Y,
                        BIG_256_56 issuer_private_key_x,
                        BIG_256_56 issuer_private_key_y,
                        csprng *rng)
{
    // 1) Set generator_2
    ECP2_BN254 generator_2;
    ecp2_BN254_set_to_generator(&generator_2);

    // 2) Choose random rx, ry <- Z_n
    BIG_256_56 rx, ry;
    big_256_56_random_mod_order(&rx, rng);
    big_256_56_random_mod_order(&ry, rng);

    // 3) Multiply generator_2 by rx: Ux = rx*generator_2
    ECP2_BN254 Ux;
    ECP2_BN254_copy(&Ux, &generator_2);
    ECP2_BN254_mul(&Ux, rx);

    // 4) Multiply generator_2 by ry: Uy = ry*generator_2
    ECP2_BN254 Uy;
    ECP2_BN254_copy(&Uy, &generator_2);
    ECP2_BN254_mul(&Uy, ry);

    // 5) Compute c = Hash( Ux | Uy | generator_2 | X | Y )
    uint8_t hash_input[645];
    assert(5*ECP2_BN254_LENGTH == sizeof(hash_input));
    ecp2_BN254_serialize(hash_input, &Ux);
    ecp2_BN254_serialize(hash_input+ECP2_BN254_LENGTH, &Uy);
    ecp2_BN254_serialize(hash_input+2*ECP2_BN254_LENGTH, &generator_2);
    ecp2_BN254_serialize(hash_input+3*ECP2_BN254_LENGTH, X);
    ecp2_BN254_serialize(hash_input+4*ECP2_BN254_LENGTH, Y);
    big_256_56_from_hash(c_out, hash_input, sizeof(hash_input));

    // 6) Compute sx = rx + c * private_key_x
    BIG_256_56 curve_order;
    BIG_256_56_rcopy(curve_order, CURVE_Order_BN254);
    big_256_56_mod_mul_and_add(sx_out, rx, *c_out, issuer_private_key_x, curve_order);    // normalizes and mod-reduces sx_out and c_out

    // 7) Compute sy = ry + c * private_key_y
    big_256_56_mod_mul_and_add(sy_out, ry, *c_out, issuer_private_key_y, curve_order);    // normalizes and mod-reduces sy_out and c_out

    // Clear intermediate, sensitive memory.
    explicit_bzero(&rx, sizeof(BIG_256_56));
    explicit_bzero(&ry, sizeof(BIG_256_56));

    return 0;
}

int issuer_schnorr_verify(BIG_256_56 c,
                          BIG_256_56 sx,
                          BIG_256_56 sy,
                          ECP2_BN254 *X,
                          ECP2_BN254 *Y)
{
    int ret = 0;

    // 1) Set generator_2
    ECP2_BN254 generator_2;
    ecp2_BN254_set_to_generator(&generator_2);

    // 2) Multiply generator_2 by sx (R1 = sx*P2)
    ECP2_BN254 R1;
    ECP2_BN254_copy(&R1, &generator_2);
    ECP2_BN254_mul(&R1, sx);

    // 3) Multiply X by c (X_c = c*X)
    ECP2_BN254 X_c;
    ECP2_BN254_copy(&X_c, X);
    ECP2_BN254_mul(&X_c, c);

    // 4) Compute difference of R1 and c*X, and save to R1 (R1 = sx*P2 - c*X)
    ECP2_BN254_sub(&R1, &X_c);
    // Nb. No need to call ECP2_BN254_affine here,
    // as R1 gets passed to ECP2_BN254_toOctet in a minute (which implicitly converts to affine)

    // 5) Multiply generator_2 by sy (R2 = sy*P2)
    ECP2_BN254 R2;
    ECP2_BN254_copy(&R2, &generator_2);
    ECP2_BN254_mul(&R2, sy);

    // 6) Multiply Y by c (Y_c = c*Y)
    ECP2_BN254 Y_c;
    ECP2_BN254_copy(&Y_c, Y);
    ECP2_BN254_mul(&Y_c, c);

    // 7) Compute difference of R2 and c*Y, and save to R2 (R2 = sy*P2 - c*Y)
    ECP2_BN254_sub(&R2, &Y_c);
    // Nb. No need to call ECP2_BN254_affine here,
    // as R1 gets passed to ECP2_BN254_toOctet in a minute (which implicitly converts to affine)

    // 8) Compute c' = Hash( R1 | R2 | generator_2 | X | Y )
    //      (modular-reduce c', too).
    uint8_t hash_input[645];
    assert(5*ECP2_BN254_LENGTH == sizeof(hash_input));
    ecp2_BN254_serialize(hash_input, &R1);
    ecp2_BN254_serialize(hash_input+ECP2_BN254_LENGTH, &R2);
    ecp2_BN254_serialize(hash_input+2*ECP2_BN254_LENGTH, &generator_2);
    ecp2_BN254_serialize(hash_input+3*ECP2_BN254_LENGTH, X);
    ecp2_BN254_serialize(hash_input+4*ECP2_BN254_LENGTH, Y);
    BIG_256_56 c_prime;
    big_256_56_from_hash(&c_prime, hash_input, sizeof(hash_input));
    BIG_256_56 curve_order;
    BIG_256_56_rcopy(curve_order, CURVE_Order_BN254);
    BIG_256_56_mod(c_prime, curve_order);

    // 6) Compare c' and c
    if (0 != BIG_256_56_comp(c_prime, c)) {
        ret = -1;
    }

    return ret;
}
