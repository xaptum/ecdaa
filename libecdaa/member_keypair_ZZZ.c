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

#include <ecdaa/member_keypair_ZZZ.h>

#include "amcl-extensions/ecp_ZZZ.h"
#include "schnorr/schnorr_ZZZ.h"

#include <assert.h>

size_t ecdaa_member_public_key_ZZZ_length(void)
{
   return ECDAA_MEMBER_PUBLIC_KEY_ZZZ_LENGTH;
}

size_t ecdaa_member_secret_key_ZZZ_length(void)
{
    return ECDAA_MEMBER_SECRET_KEY_ZZZ_LENGTH;
}

int ecdaa_member_key_pair_ZZZ_generate(struct ecdaa_member_public_key_ZZZ *pk,
                                       struct ecdaa_member_secret_key_ZZZ *sk,
                                       uint8_t *nonce,
                                       uint32_t nonce_length,
                                       ecdaa_rand_func get_random)
{
    // 1) Generate Schnorr-type keypair,
    schnorr_keygen_ZZZ(&pk->Q, &sk->sk, get_random);

    // 2) and a Schnorr-type signature on the Schnorr-type public_key itself concatenated with the nonce.
    ECP_ZZZ basepoint;
    ecp_ZZZ_set_to_generator(&basepoint);
    int sign_ret = schnorr_sign_ZZZ(&pk->c,
                                    &pk->s,
                                    NULL,
                                    nonce,
                                    nonce_length,
                                    &basepoint,
                                    &pk->Q,
                                    sk->sk,
                                    NULL,
                                    0,
                                    get_random);

    return sign_ret;
}

int ecdaa_member_public_key_ZZZ_validate(struct ecdaa_member_public_key_ZZZ *pk,
                                         uint8_t *nonce_in,
                                         uint32_t nonce_length)
{
    int ret = 0;
    
    ECP_ZZZ basepoint;
    ecp_ZZZ_set_to_generator(&basepoint);
    int sign_ret = schnorr_verify_ZZZ(pk->c,
                                      pk->s,
                                      NULL,
                                      nonce_in,
                                      nonce_length,
                                      &basepoint,
                                      &pk->Q,
                                      NULL,
                                      0);
    if (0 != sign_ret)
        ret = -1;

    return ret;
}

void ecdaa_member_public_key_ZZZ_serialize(uint8_t *buffer_out,
                                           struct ecdaa_member_public_key_ZZZ *pk)
{
    ecp_ZZZ_serialize(buffer_out, &pk->Q);
    BIG_XXX_toBytes((char*)(buffer_out + ecp_ZZZ_length()), pk->c);
    BIG_XXX_toBytes((char*)(buffer_out + ecp_ZZZ_length() + MODBYTES_XXX), pk->s);
}

int ecdaa_member_public_key_ZZZ_deserialize(struct ecdaa_member_public_key_ZZZ *pk_out,
                                            uint8_t *buffer_in,
                                            uint8_t *nonce_in,
                                            uint32_t nonce_length)
{
    int ret = 0;

    // 1) Deserialize public key and its signature.
    int deserial_ret = ecdaa_member_public_key_ZZZ_deserialize_no_check(pk_out, buffer_in);
    if (0 != deserial_ret)
        ret = -1;

    if (0 == deserial_ret) {
        // 3) Verify the schnorr signature.
        //  (This also verifies that the public key is valid).
        int schnorr_ret = ecdaa_member_public_key_ZZZ_validate(pk_out, nonce_in, nonce_length);
        if (0 != schnorr_ret)
            ret = -2;
    }

    return ret;
}

int ecdaa_member_public_key_ZZZ_deserialize_no_check(struct ecdaa_member_public_key_ZZZ *pk_out,
                                                     uint8_t *buffer_in)
{
    int ret = 0;

    // 1) Deserialize schnorr public key Q.
    int deserial_ret = ecp_ZZZ_deserialize(&pk_out->Q, buffer_in);
    if (0 != deserial_ret)
        ret = -1;

    // 2) Deserialize the schnorr signature
    BIG_XXX_fromBytes(pk_out->c, (char*)(buffer_in + ecp_ZZZ_length()));
    BIG_XXX_fromBytes(pk_out->s, (char*)(buffer_in + ecp_ZZZ_length() + MODBYTES_XXX));

    return ret;
}

void ecdaa_member_secret_key_ZZZ_serialize(uint8_t *buffer_out,
                                           struct ecdaa_member_secret_key_ZZZ *sk)
{
    BIG_XXX_toBytes((char*)buffer_out, sk->sk);
}

int ecdaa_member_secret_key_ZZZ_deserialize(struct ecdaa_member_secret_key_ZZZ *sk_out,
                                            uint8_t *buffer_in)
{
    BIG_XXX_fromBytes(sk_out->sk, (char*)buffer_in);

    return 0;
}
