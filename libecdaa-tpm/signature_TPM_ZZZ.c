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

#include <ecdaa-tpm/signature_TPM_ZZZ.h>

#include <ecdaa/credential_ZZZ.h>
#include <ecdaa/signature_ZZZ.h>
#include <ecdaa-tpm/tpm_context.h>

#include "schnorr-tpm/schnorr_TPM_ZZZ.h"

#include "amcl-extensions/ecp_ZZZ.h"

static
void randomize_credential_ZZZ(struct ecdaa_credential_ZZZ *cred,
                              ecdaa_rand_func get_random,
                              struct ecdaa_signature_ZZZ *signature_out);

int ecdaa_signature_TPM_ZZZ_sign(struct ecdaa_signature_ZZZ *signature_out,
                                 const uint8_t* message,
                                 uint32_t message_len,
                                 const uint8_t* basename,
                                 uint32_t basename_len,
                                 struct ecdaa_credential_ZZZ *cred,
                                 ecdaa_rand_func get_random,
                                 struct ecdaa_tpm_context *tpm_ctx)
{
    // 1) Randomize credential
    randomize_credential_ZZZ(cred, get_random, signature_out);

    // 2) Create a Schnorr-like signature on W concatenated with the message,
    //  where the basepoint is S.
    int sign_ret = schnorr_sign_TPM_ZZZ(&signature_out->c,
                                        &signature_out->s,
                                        &signature_out->n,
                                        &signature_out->K,
                                        message,
                                        message_len,
                                        &signature_out->S,
                                        &signature_out->W,
                                        basename,
                                        basename_len,
                                        tpm_ctx);

    return sign_ret;
}

void randomize_credential_ZZZ(struct ecdaa_credential_ZZZ *cred,
                              ecdaa_rand_func get_random,
                              struct ecdaa_signature_ZZZ *signature_out)
{
    // 1) Choose random l <- Z_p
    BIG_XXX l;
    ecp_ZZZ_random_mod_order(&l, get_random);

    // 2) Multiply the four points in the credential by l,
    //  and save to the four points in the signature

    // 2i) Multiply cred->A by l and save to sig->R (R = l*A)
    ECP_ZZZ_copy(&signature_out->R, &cred->A);
    ECP_ZZZ_mul(&signature_out->R, l);

    // 2ii) Multiply cred->B by l and save to sig->S (S = l*B)
    ECP_ZZZ_copy(&signature_out->S, &cred->B);
    ECP_ZZZ_mul(&signature_out->S, l);

    // 2iii) Multiply cred->C by l and save to sig->T (T = l*C)
    ECP_ZZZ_copy(&signature_out->T, &cred->C);
    ECP_ZZZ_mul(&signature_out->T, l);

    // 2iv) Multiply cred->D by l and save to sig->W (W = l*D)
    ECP_ZZZ_copy(&signature_out->W, &cred->D);
    ECP_ZZZ_mul(&signature_out->W, l);

    // Clear sensitive intermediate memory.
    BIG_XXX_zero(l);
}
