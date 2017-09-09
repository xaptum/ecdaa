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

#include <ecdaa/issuer_keypair.h>

#include "pairing_curve_utils.h"
#include "schnorr.h"

int ecdaa_generate_issuer_key_pair(ecdaa_issuer_public_key_t *pk,
                                   ecdaa_issuer_secret_key_t *sk,
                                   csprng *rng)
{
    // Secret key is
    // two random Bignums.
    random_num_mod_order(&sk->x, rng);
    random_num_mod_order(&sk->y, rng);

    // Public key is
    // 1) G2 generator raised to the two private key random Bignums...
    set_to_basepoint2(&pk->gpk.X);
    set_to_basepoint2(&pk->gpk.Y);
    ECP2_BN254_mul(&pk->gpk.X, sk->x);
    ECP2_BN254_mul(&pk->gpk.Y, sk->y);

    // 2) and a Schnorr-type signature to prove our knowledge of those two random Bignums.
    int sign_ret = issuer_schnorr_sign(&pk->c, &pk->sx, &pk->sy, &pk->gpk.X, &pk->gpk.Y, sk->x, sk->y, rng);
    if (0 != sign_ret)
        return -1;

    return 0;
}

void ecdaa_serialize_issuer_public_key(uint8_t *buffer_out,
                                       uint32_t *out_length,
                                       ecdaa_issuer_public_key_t *ipk)
{
    // TODO
    if (NULL == buffer_out || NULL == out_length || NULL == ipk)
        return;
}

void ecdaa_deserialize_issuer_public_key(ecdaa_issuer_public_key_t *ipk_out,
                                         uint8_t *buffer_in,
                                         uint32_t *in_length)
{
    // TODO
    if (NULL == buffer_in || NULL == in_length || NULL == ipk_out)
        return;
}

void ecdaa_serialize_issuer_secret_key(uint8_t *buffer_out,
                                       uint32_t *out_length,
                                       ecdaa_issuer_secret_key_t *isk)
{
    // TODO
    if (NULL == buffer_out || NULL == out_length || NULL == isk)
        return;
}

void ecdaa_deserialize_issuer_secret_key(ecdaa_issuer_secret_key_t *isk_out,
                                         uint8_t *buffer_in,
                                         uint32_t *in_length)
{
    // TODO
    if (NULL == buffer_in || NULL == in_length || NULL == isk_out)
        return;
}
