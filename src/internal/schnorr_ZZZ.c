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

#include "schnorr_ZZZ.h"

#include "explicit_bzero.h"
#include "../amcl-extensions/big_XXX.h"
#include "../amcl-extensions/ecp_ZZZ.h"
#include "../amcl-extensions/ecp2_ZZZ.h"

#include <ecdaa/prng.h>

#include <amcl/ecp_ZZZ.h>
#include <amcl/amcl.h>

#include <assert.h>

enum {
    THREE_ECP_LENGTH = 3*ECP_ZZZ_LENGTH,
    SIX_ECP_LENGTH = 6*ECP_ZZZ_LENGTH,
    FIVE_ECP2_LENGTH = 5*ECP2_ZZZ_LENGTH
};

static
int commit(ECP_ZZZ *P1,
           BIG_XXX private_key,
           const uint8_t *s2,
           uint32_t s2_length,
           BIG_XXX *k,
           ECP_ZZZ *P2,
           ECP_ZZZ *K,
           ECP_ZZZ *L,
           ECP_ZZZ *E,
           struct ecdaa_prng *prng);

void schnorr_keygen_ZZZ(ECP_ZZZ *public_out,
                        BIG_XXX *private_out,
                        struct ecdaa_prng *prng)
{
    ecp_ZZZ_random_mod_order(private_out, get_csprng(prng));

    ecp_ZZZ_set_to_generator(public_out);

    ECP_ZZZ_mul(public_out, *private_out);
}

int schnorr_sign_ZZZ(BIG_XXX *c_out,
                     BIG_XXX *s_out,
                     ECP_ZZZ *K_out,
                     const uint8_t *msg_in,
                     uint32_t msg_len,
                     ECP_ZZZ *basepoint,
                     ECP_ZZZ *public_key,
                     BIG_XXX private_key,
                     const uint8_t *basename,
                     uint32_t basename_len,
                     struct ecdaa_prng *prng)
{
    // 1) (Commit)
    ECP_ZZZ R, L, P2;
    BIG_XXX k;
    int commit_ret = commit(basepoint, private_key, basename, basename_len, &k, &P2, K_out, &L, &R, prng);
    if (0 != commit_ret)
        return -1;
    
    // 2) (Sign 1) Compute hash
    if (basename_len != 0) {
        // Compute c = Hash( R | basepoint | public_key | L | P2 | K_out | basename | msg_in )
        uint8_t hash_input_begin[SIX_ECP_LENGTH];
        assert(6*ECP_ZZZ_LENGTH == sizeof(hash_input_begin));
        ecp_ZZZ_serialize(hash_input_begin, &R);
        ecp_ZZZ_serialize(hash_input_begin+ECP_ZZZ_LENGTH, basepoint);
        ecp_ZZZ_serialize(hash_input_begin+2*ECP_ZZZ_LENGTH, public_key);
        ecp_ZZZ_serialize(hash_input_begin+3*ECP_ZZZ_LENGTH, &L);
        ecp_ZZZ_serialize(hash_input_begin+4*ECP_ZZZ_LENGTH, &P2);
        ecp_ZZZ_serialize(hash_input_begin+5*ECP_ZZZ_LENGTH, K_out);
        big_XXX_from_three_message_hash(c_out, hash_input_begin, sizeof(hash_input_begin), basename, basename_len, msg_in, msg_len);
    } else {
        // Compute c = Hash( R | basepoint | public_key | msg_in )
        uint8_t hash_input_begin[THREE_ECP_LENGTH];
        assert(3*ECP_ZZZ_LENGTH == sizeof(hash_input_begin));
        ecp_ZZZ_serialize(hash_input_begin, &R);
        ecp_ZZZ_serialize(hash_input_begin+ECP_ZZZ_LENGTH, basepoint);
        ecp_ZZZ_serialize(hash_input_begin+2*ECP_ZZZ_LENGTH, public_key);
        big_XXX_from_two_message_hash(c_out, hash_input_begin, sizeof(hash_input_begin), msg_in, msg_len);
    }

    // 3) (Sign 2) Compute s = k + c * private_key
    BIG_XXX curve_order;
    BIG_XXX_rcopy(curve_order, CURVE_Order_ZZZ);
    big_XXX_mod_mul_and_add(s_out, k, *c_out, private_key, curve_order);    // normalizes and mod-reduces s_out and c_out

    // Clear intermediate, sensitive memory.
    explicit_bzero(&k, sizeof(BIG_XXX));

    return 0;
}

int schnorr_verify_ZZZ(BIG_XXX c,
                       BIG_XXX s,
                       ECP_ZZZ *K,
                       const uint8_t *msg_in,
                       uint32_t msg_len,
                       ECP_ZZZ *basepoint,
                       ECP_ZZZ *public_key,
                       const uint8_t *basename,
                       uint32_t basename_len)
{
    int ret = 0;

    // 1) Check public key for validity
    // NOTE: We assume the public key was obtained from `deserialize`,
    //  which checked its validity.

    // 2) Multiply basepoint by s (R = s*P)
    ECP_ZZZ R;
    ECP_ZZZ_copy(&R, basepoint);
    ECP_ZZZ_mul(&R, s);

    // 3) Multiply public_key by c (Q_c = c *public_key)
    ECP_ZZZ Q_c;
    ECP_ZZZ_copy(&Q_c, public_key);
    ECP_ZZZ_mul(&Q_c, c);

    // 4) Compute difference of R and c*Q, and save to R (R = s*P - c*public_key)
    ECP_ZZZ_sub(&R, &Q_c);
    // Nb. No need to call ECP_ZZZ_affine here,
    // as R gets passed to ECP_ZZZ_toOctet in a minute (which implicitly converts to affine)

    // 5) Compute hash
    //      (modular-reduce c', too).
    BIG_XXX c_prime;
    if (0 != basename_len) {
        // 1,2,3,4 part ii) If checking a basename signature:
        ECP_ZZZ P2;
        ECP_ZZZ L;
        // 1ii) Find P2 by hashing basename
        int32_t hash_ret = ecp_ZZZ_fromhash(&P2, basename, basename_len);
        if (hash_ret < 0)
            return -1;

        // 2ii) Multiply P2 by s (L = s*P2)
        ECP_ZZZ_copy(&L, &P2);
        ECP_ZZZ_mul(&L, s);

        // 3) Multiply K by c (K_c = c *K)
        ECP_ZZZ K_c;
        ECP_ZZZ_copy(&K_c, K);
        ECP_ZZZ_mul(&K_c, c);

        // 4) Compute difference of L and c*K, and save to L (L = s*P2 - c*K)
        ECP_ZZZ_sub(&L, &K_c);

        // c' = Hash( R | basepoint | public_key | L | P2 | K | basename | msg_in )
        uint8_t hash_input_begin[SIX_ECP_LENGTH];
        assert(6*ECP_ZZZ_LENGTH == sizeof(hash_input_begin));
        ecp_ZZZ_serialize(hash_input_begin, &R);
        ecp_ZZZ_serialize(hash_input_begin+ECP_ZZZ_LENGTH, basepoint);
        ecp_ZZZ_serialize(hash_input_begin+2*ECP_ZZZ_LENGTH, public_key);
        ecp_ZZZ_serialize(hash_input_begin+3*ECP_ZZZ_LENGTH, &L);
        ecp_ZZZ_serialize(hash_input_begin+4*ECP_ZZZ_LENGTH, &P2);
        ecp_ZZZ_serialize(hash_input_begin+5*ECP_ZZZ_LENGTH, K);
        big_XXX_from_three_message_hash(&c_prime, hash_input_begin, sizeof(hash_input_begin), basename, basename_len, msg_in, msg_len);
        BIG_XXX curve_order;
        BIG_XXX_rcopy(curve_order, CURVE_Order_ZZZ);
        BIG_XXX_mod(c_prime, curve_order);
    } else {
        // c' = Hash( R | basepoint | public_key | msg_in )
        uint8_t hash_input_begin[THREE_ECP_LENGTH];
        assert(3*ECP_ZZZ_LENGTH == sizeof(hash_input_begin));
        ecp_ZZZ_serialize(hash_input_begin, &R);
        ecp_ZZZ_serialize(hash_input_begin+ECP_ZZZ_LENGTH, basepoint);
        ecp_ZZZ_serialize(hash_input_begin+2*ECP_ZZZ_LENGTH, public_key);
        big_XXX_from_two_message_hash(&c_prime, hash_input_begin, sizeof(hash_input_begin), msg_in, msg_len);
        BIG_XXX curve_order;
        BIG_XXX_rcopy(curve_order, CURVE_Order_ZZZ);
        BIG_XXX_mod(c_prime, curve_order);
    }

    // 6) Compare c' and c
    if (0 != BIG_XXX_comp(c_prime, c)) {
        ret = -1;
    }

    return ret;
}

int credential_schnorr_sign_ZZZ(BIG_XXX *c_out,
                                BIG_XXX *s_out,
                                ECP_ZZZ *B,
                                ECP_ZZZ *member_public_key,
                                ECP_ZZZ *D,
                                BIG_XXX issuer_private_key_y,
                                BIG_XXX credential_random,
                                struct ecdaa_prng *prng)
{
    // 1) Set generator
    ECP_ZZZ generator;
    ecp_ZZZ_set_to_generator(&generator);

    // 2) Choose random r <- Z_n
    BIG_XXX r;
    ecp_ZZZ_random_mod_order(&r, get_csprng(prng));

    // 3) Multiply generator by r: U = r*generator
    ECP_ZZZ U;
    ECP_ZZZ_copy(&U, &generator);
    ECP_ZZZ_mul(&U, r);

    // 4) Multiply member_public_key by r: V = r*member_public_key
    ECP_ZZZ V;
    ECP_ZZZ_copy(&V, member_public_key);
    ECP_ZZZ_mul(&V, r);

    // 5) Compute c = Hash( U | V | generator | B | member_public_key | D )
    uint8_t hash_input[SIX_ECP_LENGTH];
    assert(6*ECP_ZZZ_LENGTH == sizeof(hash_input));
    ecp_ZZZ_serialize(hash_input, &U);
    ecp_ZZZ_serialize(hash_input+ECP_ZZZ_LENGTH, &V);
    ecp_ZZZ_serialize(hash_input+2*ECP_ZZZ_LENGTH, &generator);
    ecp_ZZZ_serialize(hash_input+3*ECP_ZZZ_LENGTH, B);
    ecp_ZZZ_serialize(hash_input+4*ECP_ZZZ_LENGTH, member_public_key);
    ecp_ZZZ_serialize(hash_input+5*ECP_ZZZ_LENGTH, D);
    big_XXX_from_hash(c_out, hash_input, sizeof(hash_input));

    // 6) Compute ly = (credential_random x issuer_private_key_y) mod curve_order
    BIG_XXX curve_order;
    BIG_XXX_rcopy(curve_order, CURVE_Order_ZZZ);
    BIG_XXX ly;
    BIG_XXX_modmul(ly, credential_random, issuer_private_key_y, curve_order);

    // 7) Compute s = r + c * ly
    big_XXX_mod_mul_and_add(s_out, r, *c_out, ly, curve_order);    // normalizes and mod-reduces s_out and c_out

    // Clear intermediate, sensitive memory.
    explicit_bzero(&r, sizeof(BIG_XXX));

    return 0;
}

int credential_schnorr_verify_ZZZ(BIG_XXX c,
                                  BIG_XXX s,
                                  ECP_ZZZ *B,
                                  ECP_ZZZ *member_public_key,
                                  ECP_ZZZ *D)
{
    int ret = 0;

    // 1) Set generator
    ECP_ZZZ generator;
    ecp_ZZZ_set_to_generator(&generator);

    // 2) Multiply generator by s (R1 = s*P)
    ECP_ZZZ R1;
    ECP_ZZZ_copy(&R1, &generator);
    ECP_ZZZ_mul(&R1, s);

    // 3) Multiply B by c (B_c = c*B)
    ECP_ZZZ B_c;
    ECP_ZZZ_copy(&B_c, B);
    ECP_ZZZ_mul(&B_c, c);

    // 4) Compute difference of R1 and c*B, and save to R1 (R1 = s*P - c*B)
    ECP_ZZZ_sub(&R1, &B_c);
    // Nb. No need to call ECP_ZZZ_affine here,
    // as R1 gets passed to ECP_ZZZ_toOctet in a minute (which implicitly converts to affine)

    // 5) Multiply member_public_key by s (R2 = s*member_public_key)
    ECP_ZZZ R2;
    ECP_ZZZ_copy(&R2, member_public_key);
    ECP_ZZZ_mul(&R2, s);

    // 6) Multiply D by c (D_c = c*D)
    ECP_ZZZ D_c;
    ECP_ZZZ_copy(&D_c, D);
    ECP_ZZZ_mul(&D_c, c);

    // 7) Compute difference of R2 and c*D, and save to R2 (R2 = s*member_public_key - c*D)
    ECP_ZZZ_sub(&R2, &D_c);
    // Nb. No need to call ECP_ZZZ_affine here,
    // as R2 gets passed to ECP_ZZZ_toOctet in a minute (which implicitly converts to affine)

    // 8) Compute c' = Hash( R1 | R2 | generator | B | member_public_key | D )
    //      (modular-reduce c', too).
    uint8_t hash_input[SIX_ECP_LENGTH];
    assert(6*ECP_ZZZ_LENGTH == sizeof(hash_input));
    ecp_ZZZ_serialize(hash_input, &R1);
    ecp_ZZZ_serialize(hash_input+ECP_ZZZ_LENGTH, &R2);
    ecp_ZZZ_serialize(hash_input+2*ECP_ZZZ_LENGTH, &generator);
    ecp_ZZZ_serialize(hash_input+3*ECP_ZZZ_LENGTH, B);
    ecp_ZZZ_serialize(hash_input+4*ECP_ZZZ_LENGTH, member_public_key);
    ecp_ZZZ_serialize(hash_input+5*ECP_ZZZ_LENGTH, D);
    BIG_XXX c_prime;
    big_XXX_from_hash(&c_prime, hash_input, sizeof(hash_input));
    BIG_XXX curve_order;
    BIG_XXX_rcopy(curve_order, CURVE_Order_ZZZ);
    BIG_XXX_mod(c_prime, curve_order);

    // 6) Compare c' and c
    if (0 != BIG_XXX_comp(c_prime, c)) {
        ret = -1;
    }

    return ret;
}

int issuer_schnorr_sign_ZZZ(BIG_XXX *c_out,
                            BIG_XXX *sx_out,
                            BIG_XXX *sy_out,
                            ECP2_ZZZ *X,
                            ECP2_ZZZ *Y,
                            BIG_XXX issuer_private_key_x,
                            BIG_XXX issuer_private_key_y,
                            struct ecdaa_prng *prng)
{
    // 1) Set generator_2
    ECP2_ZZZ generator_2;
    ecp2_ZZZ_set_to_generator(&generator_2);

    // 2) Choose random rx, ry <- Z_n
    BIG_XXX rx, ry;
    ecp_ZZZ_random_mod_order(&rx, get_csprng(prng));
    ecp_ZZZ_random_mod_order(&ry, get_csprng(prng));

    // 3) Multiply generator_2 by rx: Ux = rx*generator_2
    ECP2_ZZZ Ux;
    ECP2_ZZZ_copy(&Ux, &generator_2);
    ECP2_ZZZ_mul(&Ux, rx);

    // 4) Multiply generator_2 by ry: Uy = ry*generator_2
    ECP2_ZZZ Uy;
    ECP2_ZZZ_copy(&Uy, &generator_2);
    ECP2_ZZZ_mul(&Uy, ry);

    // 5) Compute c = Hash( Ux | Uy | generator_2 | X | Y )
    uint8_t hash_input[FIVE_ECP2_LENGTH];
    assert(5*ECP2_ZZZ_LENGTH == sizeof(hash_input));
    ecp2_ZZZ_serialize(hash_input, &Ux);
    ecp2_ZZZ_serialize(hash_input+ECP2_ZZZ_LENGTH, &Uy);
    ecp2_ZZZ_serialize(hash_input+2*ECP2_ZZZ_LENGTH, &generator_2);
    ecp2_ZZZ_serialize(hash_input+3*ECP2_ZZZ_LENGTH, X);
    ecp2_ZZZ_serialize(hash_input+4*ECP2_ZZZ_LENGTH, Y);
    big_XXX_from_hash(c_out, hash_input, sizeof(hash_input));

    // 6) Compute sx = rx + c * private_key_x
    BIG_XXX curve_order;
    BIG_XXX_rcopy(curve_order, CURVE_Order_ZZZ);
    big_XXX_mod_mul_and_add(sx_out, rx, *c_out, issuer_private_key_x, curve_order);    // normalizes and mod-reduces sx_out and c_out

    // 7) Compute sy = ry + c * private_key_y
    big_XXX_mod_mul_and_add(sy_out, ry, *c_out, issuer_private_key_y, curve_order);    // normalizes and mod-reduces sy_out and c_out

    // Clear intermediate, sensitive memory.
    explicit_bzero(&rx, sizeof(BIG_XXX));
    explicit_bzero(&ry, sizeof(BIG_XXX));

    return 0;
}

int issuer_schnorr_verify_ZZZ(BIG_XXX c,
                              BIG_XXX sx,
                              BIG_XXX sy,
                              ECP2_ZZZ *X,
                              ECP2_ZZZ *Y)
{
    int ret = 0;

    // 1) Set generator_2
    ECP2_ZZZ generator_2;
    ecp2_ZZZ_set_to_generator(&generator_2);

    // 2) Multiply generator_2 by sx (R1 = sx*P2)
    ECP2_ZZZ R1;
    ECP2_ZZZ_copy(&R1, &generator_2);
    ECP2_ZZZ_mul(&R1, sx);

    // 3) Multiply X by c (X_c = c*X)
    ECP2_ZZZ X_c;
    ECP2_ZZZ_copy(&X_c, X);
    ECP2_ZZZ_mul(&X_c, c);

    // 4) Compute difference of R1 and c*X, and save to R1 (R1 = sx*P2 - c*X)
    ECP2_ZZZ_sub(&R1, &X_c);
    // Nb. No need to call ECP2_ZZZ_affine here,
    // as R1 gets passed to ECP2_ZZZ_toOctet in a minute (which implicitly converts to affine)

    // 5) Multiply generator_2 by sy (R2 = sy*P2)
    ECP2_ZZZ R2;
    ECP2_ZZZ_copy(&R2, &generator_2);
    ECP2_ZZZ_mul(&R2, sy);

    // 6) Multiply Y by c (Y_c = c*Y)
    ECP2_ZZZ Y_c;
    ECP2_ZZZ_copy(&Y_c, Y);
    ECP2_ZZZ_mul(&Y_c, c);

    // 7) Compute difference of R2 and c*Y, and save to R2 (R2 = sy*P2 - c*Y)
    ECP2_ZZZ_sub(&R2, &Y_c);
    // Nb. No need to call ECP2_ZZZ_affine here,
    // as R2 gets passed to ECP2_ZZZ_toOctet in a minute (which implicitly converts to affine)

    // 8) Compute c' = Hash( R1 | R2 | generator_2 | X | Y )
    //      (modular-reduce c', too).
    uint8_t hash_input[FIVE_ECP2_LENGTH];
    assert(5*ECP2_ZZZ_LENGTH == sizeof(hash_input));
    ecp2_ZZZ_serialize(hash_input, &R1);
    ecp2_ZZZ_serialize(hash_input+ECP2_ZZZ_LENGTH, &R2);
    ecp2_ZZZ_serialize(hash_input+2*ECP2_ZZZ_LENGTH, &generator_2);
    ecp2_ZZZ_serialize(hash_input+3*ECP2_ZZZ_LENGTH, X);
    ecp2_ZZZ_serialize(hash_input+4*ECP2_ZZZ_LENGTH, Y);
    BIG_XXX c_prime;
    big_XXX_from_hash(&c_prime, hash_input, sizeof(hash_input));
    BIG_XXX curve_order;
    BIG_XXX_rcopy(curve_order, CURVE_Order_ZZZ);
    BIG_XXX_mod(c_prime, curve_order);

    // 6) Compare c' and c
    if (0 != BIG_XXX_comp(c_prime, c)) {
        ret = -1;
    }

    return ret;
}

int commit(ECP_ZZZ *P1,
           BIG_XXX private_key,
           const uint8_t *s2,
           uint32_t s2_length,
           BIG_XXX *k,
           ECP_ZZZ *P2,
           ECP_ZZZ *K,
           ECP_ZZZ *L,
           ECP_ZZZ *E,
           struct ecdaa_prng *prng)
{
    // 1) Verify P1 belongs to group
    // NOTE: We assume the P1 was obtained from a call to set_to_generator,
    //  which means it's valid.

    // 2) Choose random k <- Z_n
    ecp_ZZZ_random_mod_order(k, get_csprng(prng));

    // 3) If s2 is provided,
    //  3i) Do K = [private_key](x2,y2),
    //  3ii) Do [k](x2,y2)
    if (NULL != s2 || 0 != s2_length) {
        // If any of these is non-zero, ALL must be non-zero.
        if (NULL == s2 || 0 == s2_length || NULL == K)
            return -1;

        int32_t hash_ret = ecp_ZZZ_fromhash(P2, s2, s2_length);
        if (hash_ret < 0)
            return -1;
        ECP_ZZZ_copy(L, P2);
        ECP_ZZZ_copy(K, P2);

        ECP_ZZZ_mul(K, private_key);

        ECP_ZZZ_mul(L, *k);
    }

    // 4) Multiply P1 by k: E = k*P1
    ECP_ZZZ_copy(E, P1);
    ECP_ZZZ_mul(E, *k);

    return 0;
}
