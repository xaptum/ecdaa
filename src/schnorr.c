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

#include "mpi_utils.h"
#include "pairing_curve_utils.h"

#include <amcl/ecp_BN254.h>
#include <amcl/amcl.h>

#include <assert.h>

void schnorr_keygen(ECP_BN254 *public_out,
                    BIG_256_56 *private_out,
                    csprng *rng)
{
    random_num_mod_order(private_out, rng);

    set_to_basepoint(public_out);

    ECP_BN254_mul(public_out, *private_out);
}

int convert_schnorr_public_key_from_bytes(octet *public_key_as_bytes, ECP_BN254 *public_key)
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

        if (0 == ret) {
            if (0 != check_point_membership(public_key))
                ret = -1;
        }
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
                 uint8_t *msg_in,
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
    size_t serialized_point_length = 2*MODBYTES_256_56 + 1;
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
    BIG_256_56_zero(k);

    return 0;
}

int schnorr_verify(BIG_256_56 c,
                   BIG_256_56 s,
                   uint8_t *msg_in,
                   uint32_t msg_len,
                   ECP_BN254 *basepoint,
                   ECP_BN254 *public_key)
{
    // NOTE: Assumes public_key has already been checked for validity.

    // 1) Multiply basepoint by s (R = s*P)
    ECP_BN254 R;
    ECP_BN254_copy(&R, basepoint);
    ECP_BN254_mul(&R, s);

    // 2) Multiply public_key by c (Q_c = c *public_key)
    ECP_BN254 Q_c;
    ECP_BN254_copy(&Q_c, public_key);
    ECP_BN254_mul(&Q_c, c);

    // 3) Compute difference of R and c*Q, and save to R (R = s*P - c*public_key)
    ECP_BN254_sub(&R, &Q_c);
    // Nb. No need to call ECP_BN254_affine here,
    // as R gets passed to ECP_BN254_toOctet in a minute (which implicitly converts to affine)

    // 4) Compute c' = Hash( R | basepoint | msg_in )
    //      (modular-reduce c', too).
    uint8_t hash_input_begin[195];
    size_t serialized_point_length = 2*MODBYTES_256_56 + 1;
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

    // 5) Compare c' and c
    if (0 != BIG_256_56_comp(c_prime, c)) {
        return -1;
    }

    return 0;
}

int check_point_membership(ECP_BN254 *point)
{
    ECP_BN254 point_copy;
    ECP_BN254_copy(&point_copy, point);

    BIG_256_56 curve_order;
    BIG_256_56_rcopy(curve_order, CURVE_Order_BN254);

    /* Check point is not in wrong group */
    int nb = BIG_256_56_nbits(curve_order);
    BIG_256_56 k;
    BIG_256_56_one(k);
    BIG_256_56_shl(k, (nb+4)/2);
    BIG_256_56_add(k, curve_order, k);
    BIG_256_56_sdiv(k, curve_order); /* get co-factor */

    while (BIG_256_56_parity(k) == 0) {
        ECP_BN254_dbl(&point_copy);
        BIG_256_56_fshr(k,1);
    }

    if (!BIG_256_56_isunity(k))
        ECP_BN254_mul(&point_copy,k);
    if (ECP_BN254_isinf(&point_copy))
        return -1;

    return 0;
}
