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

#include <ecdaa/signature_TPM.h>

#include <ecdaa/tpm_context.h>

#include "./internal/randomize_credential_FP256BN.h"

#include "./internal/schnorr_TPM.h"

int ecdaa_signature_TPM_sign(struct ecdaa_signature_FP256BN *signature_out,
                             const uint8_t* message,
                             uint32_t message_len,
                             const uint8_t* basename,
                             uint32_t basename_len,
                             struct ecdaa_credential_FP256BN *cred,
                             struct ecdaa_prng *prng,
                             struct ecdaa_tpm_context *tpm_ctx)
{
    // 1) Randomize credential
    randomize_credential_FP256BN(cred, prng, signature_out);

    // 2) Create a Schnorr-like signature on W concatenated with the message,
    //  where the basepoint is S.
    int sign_ret = schnorr_sign_TPM(&signature_out->c,
                                    &signature_out->s,
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
