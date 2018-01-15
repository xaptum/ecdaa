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

#ifndef ECDAA_TPM_UTILS_COMMIT_H
#define ECDAA_TPM_UTILS_COMMIT_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ecdaa/tpm_context.h>

#include "../amcl-extensions/ecp_FP256BN.h"

#include <stdint.h>

/*
 * Call TPM2_Commit, using the key handle in tpm_ctx.
 *
 * Returns:
 * 0 on success
 * -1 if TPM2_Commit fails (check tpm-ctx->last_return_code)
 * -2 if any of the elliptic curve points returned are mal-formed
 * -3 in case of an error generating the curve point from s2:
 *      - If one, but not both, of s2 or s2_length is zero
 *      - If s2_length > sizeof(TPM2B_SENSITIVE_DATA.buffer
 *      - Potentially other error (uncommon)
 */
int tpm_commit(struct ecdaa_tpm_context *tpm_ctx,
               ECP_FP256BN *P1,
               const uint8_t *s2,
               uint32_t s2_length,
               ECP_FP256BN *K,
               ECP_FP256BN *L,
               ECP_FP256BN *E);

#ifdef __cplusplus
}
#endif

#endif

