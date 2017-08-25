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

#include <xaptum-ecdaa/context.h>

#include "pairing_curve_utils.h" 

#include <amcl/amcl.h>

#include <assert.h>

int generate_issuer_key_pair(issuer_public_key_t *pk,
                             issuer_secret_key_t *sk,
                             csprng *rng)
{

    // Secret key is
    // two random Bignums.
    random_num_mod_order(&sk->x, rng);
    random_num_mod_order(&sk->y, rng);

    // Public key is
    // 1) G2 generator raised to the two private key random Bignums...
    set_to_basepoint2(&pk->X);
    set_to_basepoint2(&pk->Y);
    ECP2_BN254_mul(&pk->X, sk->x);
    ECP2_BN254_mul(&pk->Y, sk->y);

    // 2) and a Schnorr-type signature to prove our knowledge of those two random Bignums.
    BIG_256_56 rx;
    random_num_mod_order(&rx, rng);
    ECP2_BN254 Ux;
    set_to_basepoint2(&Ux);
    ECP2_BN254_mul(&Ux, rx);

    BIG_256_56 ry;
    random_num_mod_order(&ry, rng);
    ECP2_BN254 Uy;
    set_to_basepoint2(&Uy);
    ECP2_BN254_mul(&Uy, ry);

    // TODO: Finish this (construct the hash-input, do the hash, output to 'c')
    // c = Hash(Ux | Uy | basepoint | X | Y)
    // sx = rx + c*x (mod p)
    // sy = ry + c*y (mod p)

    return 0;
}

int generate_member_join_key_pair(member_join_public_key_t *pk,
                                  member_join_secret_key_t *sk,
                                  csprng *rng)
{
    // Secret key is
    // a random Bignum.
    random_num_mod_order(&sk->sk, rng);

    // Public key is
    // 1) G1 generator raised to sk...
    set_to_basepoint(&pk->Q);
    ECP_BN254_mul(&pk->Q, sk->sk);

    // 2) and a Schnorr-type signature to prove our knowledge of sk.
    BIG_256_56 r;
    random_num_mod_order(&r, rng);
    ECP_BN254 U;
    set_to_basepoint(&U);
    ECP_BN254_mul(&U, r);

    // TODO: Finish this (construct the hash-input, do the hash, output to 'c')
    // c = Hash(U | basepoint | Q | nonce)
    // sx = rx + c*x (mod p)
    // sy = ry + c*y (mod p)

    return 0;
}
