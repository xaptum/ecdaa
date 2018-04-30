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

#include "sign.h"

int tpm_sign(struct ecdaa_tpm_context *tpm_ctx,
             TPM2B_DIGEST *digest,
             TPMT_SIGNATURE *signature)
{
    TPMT_SIG_SCHEME inScheme;
    inScheme.scheme = TPM_ALG_ECDAA;
	inScheme.details.ecdaa.hashAlg = TPM_ALG_SHA256;
	inScheme.details.ecdaa.count = tpm_ctx->commit_counter;

    // Key _shouldn't_ be restricted, so no need for this
    TPMT_TK_HASHCHECK validation;
	validation.tag = TPM_ST_HASHCHECK;
	validation.hierarchy = TPM_RH_NULL;
	validation.digest.size = 0;

    tpm_ctx->last_return_code = Tss2_Sys_Sign(tpm_ctx->sapi_context,
                                              tpm_ctx->key_handle,
                                              &tpm_ctx->key_authentication_cmd,
                                              digest,
                                              &inScheme,
                                              &validation,
                                              signature,
                                              &tpm_ctx->last_auth_response_cmd);

    if (TSS2_RC_SUCCESS != tpm_ctx->last_return_code) {
        return -1;
    } else {
        return 0;
    }
}

