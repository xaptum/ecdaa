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

#include <ecdaa/member_keypair_BN254.h>

#include "./amcl-extensions/ecp_BN254.h"
#include "./internal/schnorr.h"

#include <assert.h>

size_t ecdaa_member_public_key_BN254_length(void)
{
   return ECDAA_MEMBER_PUBLIC_KEY_BN254_LENGTH;
}

size_t ecdaa_member_secret_key_BN254_length(void)
{
    return ECDAA_MEMBER_SECRET_KEY_BN254_LENGTH;
}

int ecdaa_member_key_pair_BN254_generate(struct ecdaa_member_public_key_BN254 *pk,
                                         struct ecdaa_member_secret_key_BN254 *sk,
                                         uint8_t *nonce,
                                         uint32_t nonce_length,
                                         csprng *rng)
{
    // 1) Generate Schnorr-type keypair,
    schnorr_keygen(&pk->Q, &sk->sk, rng);

    // 2) and a Schnorr-type signature on the Schnorr-type public_key itself concatenated with the nonce.
    ECP_BN254 basepoint;
    ecp_BN254_set_to_generator(&basepoint);
    int sign_ret = schnorr_sign(&pk->c,
                                &pk->s,
                                nonce,
                                nonce_length,
                                &basepoint,
                                &pk->Q,
                                sk->sk,
                                rng);

    return sign_ret;
}

int ecdaa_member_public_key_BN254_validate(struct ecdaa_member_public_key_BN254 *pk,
                                           uint8_t *nonce_in,
                                           uint32_t nonce_length)
{
    int ret = 0;
    
    ECP_BN254 basepoint;
    ecp_BN254_set_to_generator(&basepoint);
    int sign_ret = schnorr_verify(pk->c,
                                  pk->s,
                                  nonce_in,
                                  nonce_length,
                                  &basepoint,
                                  &pk->Q);
    if (0 != sign_ret)
        ret = -1;

    return ret;
}

void ecdaa_member_public_key_BN254_serialize(uint8_t *buffer_out,
                                             struct ecdaa_member_public_key_BN254 *pk)
{
    ecp_BN254_serialize(buffer_out, &pk->Q);
    BIG_256_56_toBytes((char*)(buffer_out + ecp_BN254_length()), pk->c);
    BIG_256_56_toBytes((char*)(buffer_out + ecp_BN254_length() + MODBYTES_256_56), pk->s);
}

int ecdaa_member_public_key_BN254_deserialize(struct ecdaa_member_public_key_BN254 *pk_out,
                                              uint8_t *buffer_in,
                                              uint8_t *nonce_in,
                                              uint32_t nonce_length)
{
    int ret = 0;

    // 1) Deserialize schnorr public key Q.
    int deserial_ret = ecp_BN254_deserialize(&pk_out->Q, buffer_in);
    if (0 != deserial_ret)
        ret = -1;

    // 2) Deserialize the schnorr signature
    BIG_256_56_fromBytes(pk_out->c, (char*)(buffer_in + ecp_BN254_length()));
    BIG_256_56_fromBytes(pk_out->s, (char*)(buffer_in + ecp_BN254_length() + MODBYTES_256_56));

    if (0 == deserial_ret) {
        // 3) Verify the schnorr signature.
        //  (This also verifies that the public key is valid).
        int schnorr_ret = ecdaa_member_public_key_BN254_validate(pk_out, nonce_in, nonce_length);
        if (0 != schnorr_ret)
            ret = -2;
    }

    return ret;
}

void ecdaa_member_secret_key_BN254_serialize(uint8_t *buffer_out,
                                             struct ecdaa_member_secret_key_BN254 *sk)
{
    BIG_256_56_toBytes((char*)buffer_out, sk->sk);
}

int ecdaa_member_secret_key_BN254_deserialize(struct ecdaa_member_secret_key_BN254 *sk_out,
                                              uint8_t *buffer_in)
{
    BIG_256_56_fromBytes(sk_out->sk, (char*)buffer_in);

    return 0;
}
