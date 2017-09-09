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

#include <ecdaa/sign.h>

#include <ecdaa/signature.h>
#include <ecdaa/member_keypair.h>
#include <ecdaa/credential.h>

#include "schnorr.h"
#include "pairing_curve_utils.h"

int ecdaa_sign(struct ecdaa_signature_t *signature_out,
               const uint8_t* message,
               uint32_t message_len,
               struct ecdaa_member_secret_key_t *sk,
               struct ecdaa_credential_t *cred,
               csprng *rng)
{
    // 1) Choose random l <- Z_p
    BIG_256_56 l;
    random_num_mod_order(&l, rng);

    // 2) Multiply the four points in the credential by l,
    //  and save to the four points in the signature

    // 2i) Multiply cred->A by l and save to sig->R (R = l*A)
    ECP_BN254_copy(&signature_out->R, &cred->A);
    ECP_BN254_mul(&signature_out->R, l);

    // 2ii) Multiply cred->B by l and save to sig->S (S = l*B)
    ECP_BN254_copy(&signature_out->S, &cred->B);
    ECP_BN254_mul(&signature_out->S, l);

    // 2iii) Multiply cred->C by l and save to sig->T (T = l*C)
    ECP_BN254_copy(&signature_out->T, &cred->C);
    ECP_BN254_mul(&signature_out->T, l);

    // 2iv) Multiply cred->D by l and save to sig->W (W = l*D)
    ECP_BN254_copy(&signature_out->W, &cred->D);
    ECP_BN254_mul(&signature_out->W, l);

    // 3) Create a Schnorr-like signature on W concatenated with the message,
    //  where the basepoint is S.
    int sign_ret = schnorr_sign(&signature_out->c,
                                &signature_out->s,
                                message,
                                message_len,
                                &signature_out->S,
                                &signature_out->W,
                                sk->sk,
                                rng);
    
    // Clear sensitive intermediate memory.
    BIG_256_56_zero(l);

    return sign_ret;
}
