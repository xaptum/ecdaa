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

#include <ecdaa/member_keypair_TPM.h>

#include "./amcl-extensions/ecp_FP256BN.h"
#include "./internal/schnorr_TPM.h"

#include <assert.h>

int ecdaa_member_key_pair_TPM_generate(struct ecdaa_member_public_key_FP256BN *pk,
                                       uint8_t *nonce,
                                       uint32_t nonce_length,
                                       struct ecdaa_tpm_context *tpm_ctx)
{
    int ret = 0;

    // 1) Copy public key from TPM.
    ECP_FP256BN_copy(&pk->Q, &tpm_ctx->public_key);

    // 2) and a Schnorr-type signature on the Schnorr-type public_key itself concatenated with the nonce.
    ECP_FP256BN basepoint;
    ecp_FP256BN_set_to_generator(&basepoint);
    ret = schnorr_sign_TPM(&pk->c,
                           &pk->s,
                           NULL,
                           nonce,
                           nonce_length,
                           &basepoint,
                           &pk->Q,
                           NULL,
                           0,
                           tpm_ctx);

    return ret;
}
