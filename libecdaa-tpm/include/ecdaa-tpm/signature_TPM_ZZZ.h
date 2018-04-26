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

#ifndef ECDAA_SIGNATURE_TPM_SIGN_ZZZ_H
#define ECDAA_SIGNATURE_TPM_SIGN_ZZZ_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ecdaa/signature_ZZZ.h>

#include <stdint.h>

struct ecdaa_tpm_context;

/*
 * Create an ECDAA signature, using a TPM.
 *
 * Returns:
 * 0 on success
 * -1 if unable to create signature
 */
int ecdaa_signature_TPM_ZZZ_sign(struct ecdaa_signature_ZZZ *signature_out,
                                 const uint8_t* message,
                                 uint32_t message_len,
                                 const uint8_t* basename,
                                 uint32_t basename_len,
                                 struct ecdaa_credential_ZZZ *cred,
                                 struct ecdaa_prng *prng,
                                 struct ecdaa_tpm_context *tpm_ctx);

#ifdef __cplusplus
}
#endif

#endif

