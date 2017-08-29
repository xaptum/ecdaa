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

#include <xaptum-ecdaa/member_keypair.h>

#include <xaptum-ecdaa/issuer_nonce.h>

#include "schnorr.h"
#include "pairing_curve_utils.h"

int ecdaa_generate_member_key_pair(ecdaa_member_public_key_t *pk,
                                   ecdaa_member_secret_key_t *sk,
                                   struct ecdaa_issuer_nonce_t *nonce,
                                   csprng *rng)
{
    // 1) Generate Schnorr-type keypair,
    schnorr_keygen(&pk->Q, &sk->sk, rng);

    // 2) and a Schnorr-type signature on the Schnorr-type public_key itself concatenated with the nonce.
    ECP_BN254 basepoint;
    set_to_basepoint(&basepoint);
    int sign_ret = schnorr_sign(&pk->c,
                                &pk->s,
                                nonce->data,
                                sizeof(ecdaa_issuer_nonce_t),
                                &basepoint,
                                &pk->Q,
                                sk->sk,
                                rng);

    return sign_ret;
}

