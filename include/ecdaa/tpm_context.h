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

#ifndef ECDAA_TPM_CONTEXT_H
#define ECDAA_TPM_CONTEXT_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#ifndef TPM_CONTEXT_BUFFER_SIZE
#define TPM_CONTEXT_BUFFER_SIZE 5120
#endif

#include <tss2/tss2_sys.h>

#include <amcl/ecp_FP256BN.h>

struct ecdaa_tpm_context {
    uint8_t context_buffer[TPM_CONTEXT_BUFFER_SIZE];

    TSS2_SYS_CONTEXT *sapi_context;
    uint16_t commit_counter;
    TPM_HANDLE key_handle;

    TPMS_AUTH_COMMAND key_authentication;
    TPMS_AUTH_COMMAND *key_authentication_array[1];    // for passing into functions
    TSS2_SYS_CMD_AUTHS key_authentication_cmd;    // for passing into functions

    TPMS_AUTH_RESPONSE last_auth_response;
    TPMS_AUTH_RESPONSE *last_auth_response_array[1];    // for passing into functions
    TSS2_SYS_RSP_AUTHS last_auth_response_cmd;    // for passing into functions

    TSS2_RC last_return_code;
};

/*
 * Initialize an ecdaa_tpm_context object and connect to a TPM listening on a TCP socket.
 *
 * Only password authentication (for the ownership of the Schnorr keypair) is supported.
 *
 * Returns:
 * 0 on success
 * -1 on failure
 */
int ecdaa_tpm_context_init_socket(struct ecdaa_tpm_context *tpm_ctx,
                                  TPM_HANDLE key_handle_in,
                                  const char *hostname,
                                  const char *port,
                                  const char *key_password,
                                  uint16_t key_password_length);

void ecdaa_tpm_context_free(struct ecdaa_tpm_context *tpm_ctx);

#ifdef __cplusplus
}
#endif

#endif

