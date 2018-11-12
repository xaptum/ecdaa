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

#ifndef ECDAA_TPM_UTILS_SIGN_H
#define ECDAA_TPM_UTILS_SIGN_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ecdaa-tpm/tpm_context.h>

#include <tss2/tss2_sys.h>

/*
 * Call TPM2_Commit, using the key handle in tpm_ctx.
 *
 * Returns:
 * 0 on success
 * -1 if TPM2_Sign fails (check tpm-ctx->last_return_code)
 */
int tpm_sign(struct ecdaa_tpm_context *tpm_ctx,
             TPM2B_DIGEST *digest,
             TPMT_SIGNATURE *signature);

#ifdef __cplusplus
}
#endif

#endif

