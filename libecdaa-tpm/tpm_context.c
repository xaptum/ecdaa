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

#include <ecdaa-tpm/tpm_context.h>

#include <assert.h>
#include <string.h>

static
TSS2_SYS_CONTEXT*
sapi_ctx_init(uint8_t *memory_pool,
             size_t memory_pool_size,
             TSS2_TCTI_CONTEXT *tcti_context);

static int tpm_context_init_common(struct ecdaa_tpm_context *tpm_ctx,
                                   TPM2_HANDLE key_handle_in,
                                   const char *password,
                                   uint16_t password_length);

int ecdaa_tpm_context_init(struct ecdaa_tpm_context *tpm_ctx,
                           TPM2_HANDLE key_handle_in,
                           const char *key_password,
                           uint16_t key_password_length,
                           TSS2_TCTI_CONTEXT *tcti_context)
{
    tpm_ctx->sapi_context = sapi_ctx_init(tpm_ctx->context_buffer, sizeof(tpm_ctx->context_buffer), tcti_context);
    if (NULL == tpm_ctx->sapi_context)
        return -1;

    if (0 != tpm_context_init_common(tpm_ctx, key_handle_in, key_password, key_password_length))
        return -1;

    return 0;
}

void ecdaa_tpm_context_free(struct ecdaa_tpm_context *tpm_ctx)
{
    if (tpm_ctx->sapi_context != NULL) {
        Tss2_Sys_Finalize(tpm_ctx->sapi_context);
    }
}

TSS2_SYS_CONTEXT*
sapi_ctx_init(uint8_t *memory_pool,
             size_t memory_pool_size,
             TSS2_TCTI_CONTEXT *tcti_context)
{
    size_t sapi_ctx_size = Tss2_Sys_GetContextSize(0);
    if (memory_pool_size < sapi_ctx_size)
        return NULL;
    TSS2_SYS_CONTEXT *sapi_ctx = (TSS2_SYS_CONTEXT*)memory_pool;

    TSS2_RC init_ret;

    TSS2_ABI_VERSION abi_version = TSS2_ABI_VERSION_CURRENT;
    init_ret = Tss2_Sys_Initialize(sapi_ctx,
                                   sapi_ctx_size,
                                   tcti_context,
                                   &abi_version);
    if (TSS2_RC_SUCCESS != init_ret)
        return NULL;

    return sapi_ctx;
}

int tpm_context_init_common(struct ecdaa_tpm_context *tpm_ctx,
                            TPM2_HANDLE key_handle_in,
                            const char *key_password,
                            uint16_t key_password_length)
{
    if (key_password_length > sizeof(tpm_ctx->key_authentication_cmd.auths[0].hmac.buffer))
        return -1;

    tpm_ctx->commit_counter = UINT16_MAX;

    tpm_ctx->key_handle = key_handle_in;

    static TPMA_SESSION empty_session_attributes = {0};    // attributes for password either can't be set or don't make sense

    tpm_ctx->key_authentication_cmd.auths[0].sessionHandle = TPM2_RS_PW;
    tpm_ctx->key_authentication_cmd.auths[0].nonce.size = 0; // TODO: Does a nonce ever make sense for password authentication?
    tpm_ctx->key_authentication_cmd.auths[0].sessionAttributes = empty_session_attributes;
    tpm_ctx->key_authentication_cmd.auths[0].hmac.size = key_password_length;
    if (0 != key_password_length) {
        if (NULL == key_password)
            return -1;
        memcpy(tpm_ctx->key_authentication_cmd.auths[0].hmac.buffer, key_password, key_password_length);
    }
    tpm_ctx->key_authentication_cmd.count = 1;

    tpm_ctx->last_auth_response_cmd.auths[0].nonce.size = 0;
    tpm_ctx->last_auth_response_cmd.auths[0].sessionAttributes = empty_session_attributes;
    tpm_ctx->last_auth_response_cmd.auths[0].hmac.size = 0;
    tpm_ctx->last_auth_response_cmd.count = 1;

    return 0;
}

