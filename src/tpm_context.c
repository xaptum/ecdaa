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

#include <ecdaa/tpm_context.h>

#include "./amcl-extensions/ecp_FP256BN.h"

#include <tss2/tss2_tcti_socket.h>

#include <assert.h>
#include <string.h>

static TSS2_SYS_CONTEXT* sapi_ctx_init(const char* hostname,
                                       const char* port,
                                       uint8_t *memory_pool,
                                       size_t memory_pool_size);

static int tpm_context_init_common(struct ecdaa_tpm_context *tpm_ctx,
                                   ECP_FP256BN *public_key_in,
                                   TPM_HANDLE key_handle_in,
                                   const char *password,
                                   uint16_t password_length);

int ecdaa_tpm_context_init_socket(struct ecdaa_tpm_context *tpm_ctx,
                                  ECP_FP256BN *public_key_in,
                                  TPM_HANDLE key_handle_in,
                                  const char *hostname,
                                  const char *port,
                                  const char *password,
                                  uint16_t password_length)
{
    tpm_ctx->sapi_context = sapi_ctx_init(hostname, port, tpm_ctx->context_buffer, sizeof(tpm_ctx->context_buffer));
    if (NULL == tpm_ctx->sapi_context)
        return -1;

    if (0 != tpm_context_init_common(tpm_ctx, public_key_in, key_handle_in, password, password_length))
        return -1;

    return 0;
}

void ecdaa_tpm_context_free(struct ecdaa_tpm_context *tpm_ctx)
{
    TSS2_TCTI_CONTEXT *tcti_context = NULL;
    TSS2_RC rc;

    if (tpm_ctx->sapi_context != NULL) {
        rc = Tss2_Sys_GetTctiContext(tpm_ctx->sapi_context, &tcti_context);

        if (TSS2_RC_SUCCESS == rc) {
            tss2_tcti_finalize(tcti_context);
        }

        Tss2_Sys_Finalize(tpm_ctx->sapi_context);
    }
}

TSS2_SYS_CONTEXT*
sapi_ctx_init(const char *hostname,
              const char *port,
              uint8_t *memory_pool,
              size_t memory_pool_size)
{
    size_t tcti_ctx_size = tss2_tcti_getsize_socket();
    if (memory_pool_size < tcti_ctx_size)
        return NULL;
    TSS2_TCTI_CONTEXT *tcti_ctx = (TSS2_TCTI_CONTEXT*)&memory_pool[0];

    size_t sapi_ctx_size = Tss2_Sys_GetContextSize(0);
    if ((memory_pool_size - tcti_ctx_size) < sapi_ctx_size)
        return NULL;
    TSS2_SYS_CONTEXT *sapi_ctx = (TSS2_SYS_CONTEXT*)&memory_pool[tcti_ctx_size];
    
    TSS2_RC init_ret;

    init_ret = tss2_tcti_init_socket(hostname, port, tcti_ctx);
    if (TSS2_RC_SUCCESS != init_ret)
        return NULL;

    TSS2_ABI_VERSION abi_version = TSS2_ABI_CURRENT_VERSION;
    init_ret = Tss2_Sys_Initialize(sapi_ctx,
                                   sapi_ctx_size,
                                   tcti_ctx,
                                   &abi_version);
    if (TSS2_RC_SUCCESS != init_ret)
        return NULL;

    return sapi_ctx;
}

int tpm_context_init_common(struct ecdaa_tpm_context *tpm_ctx,
                            ECP_FP256BN *public_key_in,
                            TPM_HANDLE key_handle_in,
                            const char *key_password,
                            uint16_t key_password_length)
{
    if (key_password_length > sizeof(tpm_ctx->key_authentication.hmac.buffer))
        return -1;

    tpm_ctx->commit_counter = UINT16_MAX;

    ECP_FP256BN_copy(&tpm_ctx->public_key, public_key_in);

    tpm_ctx->key_handle = key_handle_in;

    static TPMA_SESSION empty_session_attributes = {0};    // attributes for password either can't be set or don't make sense

    tpm_ctx->key_authentication.sessionHandle = TPM_RS_PW;
    tpm_ctx->key_authentication.nonce.size = 0; // TODO: Does a nonce ever make sense for password authentication?
    tpm_ctx->key_authentication.sessionAttributes = empty_session_attributes;
    tpm_ctx->key_authentication.hmac.size = key_password_length;
    if (0 != key_password_length) {
        if (NULL == key_password)
            return -1;
        memcpy(tpm_ctx->key_authentication.hmac.buffer, key_password, key_password_length);
    }
    tpm_ctx->key_authentication_array[0] = &tpm_ctx->key_authentication;
    tpm_ctx->key_authentication_cmd.cmdAuths = &tpm_ctx->key_authentication_array[0];
    tpm_ctx->key_authentication_cmd.cmdAuthsCount = 1;

    tpm_ctx->last_auth_response.nonce.size = 0;
    tpm_ctx->last_auth_response.sessionAttributes = empty_session_attributes;
    tpm_ctx->last_auth_response.hmac.size = 0;
    tpm_ctx->last_auth_response_array[0] = &tpm_ctx->last_auth_response;
    tpm_ctx->last_auth_response_cmd.rspAuths = &tpm_ctx->last_auth_response_array[0];
    tpm_ctx->last_auth_response_cmd.rspAuthsCount = 1;

    return 0;
}

