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

#include <ecdaa-tpm/member_keypair_TPM_ZZZ.h>

#include "amcl-extensions/ecp_ZZZ.h"
#include "schnorr-tpm/schnorr_TPM_ZZZ.h"

#include <assert.h>

int ecdaa_member_key_pair_TPM_ZZZ_generate(struct ecdaa_member_public_key_ZZZ *pk,
                                           const uint8_t *serialized_public_key_in,
                                           uint8_t *nonce,
                                           uint32_t nonce_length,
                                           struct ecdaa_tpm_context *tpm_ctx)
{
    int ret = 0;

    // 1) Copy public key
    if (0 != ecp_ZZZ_deserialize(&pk->Q, (uint8_t*)serialized_public_key_in))
        return -1;

    // 2) and a Schnorr-type signature on the Schnorr-type public_key itself concatenated with the nonce.
    ECP_ZZZ basepoint;
    ecp_ZZZ_set_to_generator(&basepoint);
    ret = schnorr_sign_TPM_ZZZ(&pk->c,
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
