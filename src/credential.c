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

#include <xaptum-ecdaa/credential.h>

#include "schnorr.h"
#include "explicit_bzero.h"

#include <xaptum-ecdaa/issuer_keypair.h>
#include <xaptum-ecdaa/member_keypair.h>

#include "pairing_curve_utils.h"

int ecdaa_generate_credential(ecdaa_credential_t *cred,
                              ecdaa_credential_signature_t *cred_sig_out,
                              struct ecdaa_issuer_secret_key_t *issuer_sk,
                              struct ecdaa_member_public_key_t *member_pk,
                              csprng *rng)
{
    int ret = 0;

    BIG_256_56 curve_order;
    BIG_256_56_rcopy(curve_order, CURVE_Order_BN254);

    // 1) Choose random l <- Z_p
    BIG_256_56 l;
    random_num_mod_order(&l, rng);

    // 2) Multiply generator by l and save to cred->A (A = l*P)
    set_to_basepoint(&cred->A);
    ECP_BN254_mul(&cred->A, l);

    // 3) Multiply A by my secret y and save to cred->B (B = y*A)
    ECP_BN254_copy(&cred->B, &cred->A);
    ECP_BN254_mul(&cred->B, issuer_sk->y);

    // 4) Mod-multiply l and y
    BIG_256_56 ly;
    BIG_256_56_modmul(ly, l, issuer_sk->y, curve_order);

    // 5) Multiply member's public_key by ly and save to cred->D (D = ly*Q)
    ECP_BN254_copy(&cred->D, &member_pk->Q);
    ECP_BN254_mul(&cred->D, ly);

    // 6) Multiply A by my secret x (store in cred->C temporarily)
    ECP_BN254_copy(&cred->C, &cred->A);
    ECP_BN254_mul(&cred->C, issuer_sk->x);

    // 7) Mod-multiply ly (see step 4) by my secret x
    BIG_256_56 xyl;
    BIG_256_56_modmul(xyl, ly, issuer_sk->x, curve_order);

    // 8) Multiply member's public_key by xyl
    ECP_BN254 Qxyl;
    ECP_BN254_copy(&Qxyl, &member_pk->Q);
    ECP_BN254_mul(&Qxyl, xyl);

    // 9) Add Ax and xyl*Q and save to cred->C (C = x*A + xyl*Q)
    ECP_BN254_add(&cred->C, &Qxyl);
    // Nb. No need to call ECP_BN254_affine here,
    // as C always gets multiplied during signing (which implicitly converts to affine)

    // 10) Perform a Schnorr-like signature,
    //  to prove the credential was properly constructed by someone with knowledge of y.
    int schnorr_ret = issuer_schnorr_sign(&cred_sig_out->c,
                                          &cred_sig_out->s,
                                          &cred->B,
                                          &member_pk->Q,
                                          &cred->D,
                                          issuer_sk->y,
                                          l,
                                          rng);
    if (0 != schnorr_ret)
        ret = -1;

    // Clear sensitive intermediate memory
    explicit_bzero(&l, sizeof(BIG_256_56));

    return ret;
}

void ecdaa_serialize_credential(uint8_t *buffer_out,
                                uint32_t *out_length,
                                ecdaa_credential_t *credential)
{
    // TODO
    if (NULL == buffer_out || NULL == out_length || NULL == credential)
        return;
}

void ecdaa_deserialize_credential(ecdaa_credential_t *credential_out,
                                  uint8_t *buffer_in,
                                  uint32_t *in_length)
{
    // TODO
    if (NULL == buffer_in || NULL == in_length || NULL == credential_out)
        return;
}
