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
    // two random Bignums
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

    return 0;
}
