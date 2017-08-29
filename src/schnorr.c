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
#include "mpi_utils.h"
#include "pairing_curve_utils.h"

#include <amcl/ecp_BN254.h>
#include <amcl/amcl.h>

#include <assert.h>

static const size_t serialized_point_length = 2*MODBYTES_256_56 + 1;

void schnorr_keygen(ECP_BN254 *public_out,
                    BIG_256_56 *private_out,
                    csprng *rng)
{
    random_num_mod_order(private_out, rng);

    set_to_basepoint(public_out);

    ECP_BN254_mul(public_out, *private_out);
}

int convert_schnorr_public_key_from_bytes(const octet *public_key_as_bytes, ECP_BN254 *public_key)
{
    // Avoid returning early, to mitigate timing attacks.
    int ret = 0;

    BIG_256_56 curve_order;
    BIG_256_56_rcopy(curve_order, CURVE_Order_BN254);

    BIG_256_56 Q_x, Q_y;
    assert(public_key_as_bytes->val[0] == 0x04);
    BIG_256_56_fromBytes(Q_x, &(public_key_as_bytes->val[1]));
    BIG_256_56_fromBytes(Q_y, &(public_key_as_bytes->val[MODBYTES_256_56+1]));

    // Check that coordinates aren't too large.
    if (BIG_256_56_comp(Q_x, curve_order) >= 0)
        ret = -1;
    if (BIG_256_56_comp(Q_y, curve_order) >= 0)
        ret = -1;

    if (0 == ret) {
        // Copy putative group key into output
        if (1 != ECP_BN254_set(public_key, Q_x, Q_y))
            ret = -1;

        if (ECP_BN254_isinf(public_key))
            ret = -1;
    }

    return ret;
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
    if (0 != check_point_membership(basepoint))
        return -1;

    // 2) (Commit 2) Choose random k <- Z_n
    BIG_256_56 k;
    random_num_mod_order(&k, rng);

    // 3) (Commit 3) Multiply basepoint by k: R = k*basepoint
    ECP_BN254 R;
    ECP_BN254_copy(&R, basepoint);
    ECP_BN254_mul(&R, k);

    // 4) (Sign 1) Compute c = Hash( R | basepoint | public_key | msg_in )
    uint8_t hash_input_begin[195];
    assert(3*serialized_point_length == sizeof(hash_input_begin));
    octet R_serialized = {.len = 0,
                          .max = serialized_point_length,
                          .val = (char*)hash_input_begin};
    octet basepoint_serialized = {.len = 0,
                                  .max = serialized_point_length,
                                  .val = (char*)hash_input_begin + serialized_point_length};
    octet publickey_serialized = {.len = 0,
                                  .max = serialized_point_length,
                                  .val = (char*)hash_input_begin + 2*serialized_point_length};
    ECP_BN254_toOctet(&R_serialized, &R);   // Serialize R into buffer
    ECP_BN254_toOctet(&basepoint_serialized, basepoint);   // Serialize basepoint into buffer
    ECP_BN254_toOctet(&publickey_serialized, public_key);   // Serialize public_key into buffer
    hash_into_mpi_two(c_out, hash_input_begin, sizeof(hash_input_begin), msg_in, msg_len);

    // 5) (Sign 2) Compute s = k + c * private_key
    BIG_256_56 curve_order;
    BIG_256_56_rcopy(curve_order, CURVE_Order_BN254);
    mpi_mod_mul_and_add(s_out, k, *c_out, private_key, curve_order);    // normalizes and mod-reduces s_out and c_out

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
    if (0 != check_point_membership(public_key))
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
    assert(3*serialized_point_length == sizeof(hash_input_begin));
    octet R_serialized = {.len = 0,
                          .max = serialized_point_length,
                          .val = (char*)hash_input_begin};
    octet basepoint_serialized = {.len = 0,
                                  .max = serialized_point_length,
                                  .val = (char*)hash_input_begin + serialized_point_length};
    octet publickey_serialized = {.len = 0,
                                  .max = serialized_point_length,
                                  .val = (char*)hash_input_begin + 2*serialized_point_length};
    ECP_BN254_toOctet(&R_serialized, &R);   // Serialize R into buffer
    ECP_BN254_toOctet(&basepoint_serialized, basepoint);   // Serialize basepoint into buffer
    ECP_BN254_toOctet(&publickey_serialized, public_key);   // Serialize public_key into buffer
    BIG_256_56 c_prime;
    hash_into_mpi_two(&c_prime, hash_input_begin, sizeof(hash_input_begin), msg_in, msg_len);
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
    set_to_basepoint(&generator);

    // 2) Choose random r <- Z_n
    BIG_256_56 r;
    random_num_mod_order(&r, rng);

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
    assert(6*serialized_point_length == sizeof(hash_input));
    octet U_serialized = {.len = 0,
                          .max = serialized_point_length,
                          .val = (char*)hash_input};
    octet V_serialized = {.len = 0,
                          .max = serialized_point_length,
                          .val = (char*)hash_input + serialized_point_length};
    octet generator_serialized = {.len = 0,
                                  .max = serialized_point_length,
                                  .val = (char*)hash_input + 2*serialized_point_length};
    octet B_serialized = {.len = 0,
                          .max = serialized_point_length,
                          .val = (char*)hash_input + 3*serialized_point_length};
    octet publickey_serialized = {.len = 0,
                                  .max = serialized_point_length,
                                  .val = (char*)hash_input + 4*serialized_point_length};
    octet D_serialized = {.len = 0,
                          .max = serialized_point_length,
                          .val = (char*)hash_input + 5*serialized_point_length};
    ECP_BN254_toOctet(&U_serialized, &U);   // Serialize U into buffer
    ECP_BN254_toOctet(&V_serialized, &V);   // Serialize V into buffer
    ECP_BN254_toOctet(&generator_serialized, &generator);   // Serialize generator into buffer
    ECP_BN254_toOctet(&B_serialized, B);   // Serialize B into buffer
    ECP_BN254_toOctet(&publickey_serialized, member_public_key);   // Serialize member_public_key into buffer
    ECP_BN254_toOctet(&D_serialized, D);   // Serialize D into buffer
    hash_into_mpi(c_out, hash_input, sizeof(hash_input));

    // 6) Compute ly = (credential_random x issuer_private_key_y) mod curve_order
    BIG_256_56 curve_order;
    BIG_256_56_rcopy(curve_order, CURVE_Order_BN254);
    BIG_256_56 ly;
    BIG_256_56_modmul(ly, credential_random, issuer_private_key_y, curve_order);

    // 7) Compute s = r + c * ly
    mpi_mod_mul_and_add(s_out, r, *c_out, ly, curve_order);    // normalizes and mod-reduces s_out and c_out

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
    set_to_basepoint(&generator);

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
    assert(6*serialized_point_length == sizeof(hash_input));
    octet R1_serialized = {.len = 0,
                           .max = serialized_point_length,
                           .val = (char*)hash_input};
    octet R2_serialized = {.len = 0,
                           .max = serialized_point_length,
                           .val = (char*)hash_input + serialized_point_length};
    octet generator_serialized = {.len = 0,
                                  .max = serialized_point_length,
                                  .val = (char*)hash_input + 2*serialized_point_length};
    octet B_serialized = {.len = 0,
                          .max = serialized_point_length,
                          .val = (char*)hash_input + 3*serialized_point_length};
    octet publickey_serialized = {.len = 0,
                                  .max = serialized_point_length,
                                  .val = (char*)hash_input + 4*serialized_point_length};
    octet D_serialized = {.len = 0,
                          .max = serialized_point_length,
                          .val = (char*)hash_input + 5*serialized_point_length};
    ECP_BN254_toOctet(&R1_serialized, &R1);   // Serialize R1 into buffer
    ECP_BN254_toOctet(&R2_serialized, &R2);   // Serialize R2 into buffer
    ECP_BN254_toOctet(&generator_serialized, &generator);   // Serialize generator into buffer
    ECP_BN254_toOctet(&B_serialized, B);   // Serialize B into buffer
    ECP_BN254_toOctet(&publickey_serialized, member_public_key);   // Serialize member_public_key into buffer
    ECP_BN254_toOctet(&D_serialized, D);   // Serialize D into buffer

    BIG_256_56 c_prime;
    hash_into_mpi(&c_prime, hash_input, sizeof(hash_input));
    BIG_256_56 curve_order;
    BIG_256_56_rcopy(curve_order, CURVE_Order_BN254);
    BIG_256_56_mod(c_prime, curve_order);

    // 6) Compare c' and c
    if (0 != BIG_256_56_comp(c_prime, c)) {
        ret = -1;
    }

    return ret;
}
