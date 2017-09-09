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

#include <ecdaa/group_public_key.h>

size_t serialized_issuer_public_key_length(void) {
    return SERIALIZED_ISSUER_PUBLIC_KEY_LENGTH;
}

size_t serialized_issuer_secret_key_length() {
    return SERIALIZED_ISSUER_SECRET_KEY_LENGTH;
}

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

int ecdaa_validate_issuer_public_key(ecdaa_issuer_public_key_t *ipk)
{
    int ret = 0;

    int schnorr_ret = issuer_schnorr_verify(ipk->c, ipk->sx, ipk->sy, &ipk->gpk.X, &ipk->gpk.Y);
    if (0 != schnorr_ret)
        ret = -1;

    return ret;
}

void ecdaa_serialize_issuer_public_key(uint8_t *buffer_out,
                                       ecdaa_issuer_public_key_t *ipk)
{
    ecdaa_serialize_group_public_key(buffer_out, &ipk->gpk);

    BIG_256_56_toBytes((char*)(buffer_out + serialized_group_public_key_length()), ipk->c);
    BIG_256_56_toBytes((char*)(buffer_out + serialized_group_public_key_length() + MODBYTES_256_56), ipk->sx);
    BIG_256_56_toBytes((char*)(buffer_out + serialized_group_public_key_length() + 2*MODBYTES_256_56), ipk->sy);
}

int ecdaa_deserialize_issuer_public_key(ecdaa_issuer_public_key_t *ipk_out,
                                        uint8_t *buffer_in)
{
    int ret = 0;

    // 1) Deserialize the gpk
    //  (This also checks gpk.X and gpk.Y for membership in G2)
    int deserial_ret = ecdaa_deserialize_group_public_key(&ipk_out->gpk, buffer_in);
    if (0 != deserial_ret)
        ret = -1;

    // 2) Deserialize the issuer_schnorr signature
    BIG_256_56_fromBytes(ipk_out->c, (char*)(buffer_in + serialized_group_public_key_length()));
    BIG_256_56_fromBytes(ipk_out->sx, (char*)(buffer_in + serialized_group_public_key_length() + MODBYTES_256_56));
    BIG_256_56_fromBytes(ipk_out->sy, (char*)(buffer_in + serialized_group_public_key_length() + 2*MODBYTES_256_56));

    // 3) Check the signature
    int sign_ret = ecdaa_validate_issuer_public_key(ipk_out);
    if (0 != sign_ret)
        ret = -2;

    return ret;
}

void ecdaa_serialize_issuer_secret_key(uint8_t *buffer_out,
                                       ecdaa_issuer_secret_key_t *isk)
{
    BIG_256_56_toBytes((char*)buffer_out, isk->x);
    BIG_256_56_toBytes((char*)(buffer_out + MODBYTES_256_56), isk->y);
}

int ecdaa_deserialize_issuer_secret_key(ecdaa_issuer_secret_key_t *isk_out,
                                        uint8_t *buffer_in)
{
    BIG_256_56_fromBytes(isk_out->x, (char*)buffer_in);
    BIG_256_56_fromBytes(isk_out->y, (char*)(buffer_in + MODBYTES_256_56));

    return 0;
}
