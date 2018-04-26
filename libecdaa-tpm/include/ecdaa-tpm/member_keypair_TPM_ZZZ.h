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

#ifndef ECDAA_MEMBER_KEYPAIR_TPM_ZZZ_H
#define ECDAA_MEMBER_KEYPAIR_TPM_ZZZ_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ecdaa/member_keypair_ZZZ.h>
#include <ecdaa-tpm/tpm_context.h>

/*
 * Generate a fresh `ecdaa_member_public_key_ZZZ`, using a TPM.
 *
 * Returns:
 * 0 on success
 * -1 on error
 */
int ecdaa_member_key_pair_TPM_ZZZ_generate(struct ecdaa_member_public_key_ZZZ *pk_out,
                                           const uint8_t *serialized_public_key_in,
                                           uint8_t *nonce,
                                           uint32_t nonce_length,
                                           struct ecdaa_tpm_context *tpm_ctx);

#ifdef __cplusplus
}
#endif

#endif

