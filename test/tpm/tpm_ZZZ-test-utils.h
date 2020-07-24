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

#include "amcl-extensions/ecp_ZZZ.h"

#include <ecdaa-tpm/tpm_context.h>

#include <tss2/tss2_sys.h>
#include <tss2/tss2_tcti_mssim.h>
#include <tss2/tss2_tcti_device.h>

#include <string.h>

const char *pub_key_filename = "pub_key.txt";
const char *handle_filename = "handle.txt";

static
int read_public_key_from_files(uint8_t *public_key,
                               TPM2_HANDLE *key_handle,
                               const char *pub_key_filename,
                               const char *handle_filename);

struct tpm_test_context {
    struct ecdaa_tpm_context tpm_ctx;
    uint8_t serialized_public_key[ECP_ZZZ_LENGTH];
    ECP_ZZZ public_key;
    unsigned char tcti_buffer[256];
    TSS2_TCTI_CONTEXT *tcti_context;
};

static
int tpm_initialize(struct tpm_test_context *ctx)
{
    const char *mssim_conf = "host=localhost,port=2321";
    const char *device_conf = "/dev/tpm0";

    int ret = 0;

    TPM2_HANDLE key_handle = 0;

    if (0 != read_public_key_from_files(ctx->serialized_public_key, &key_handle, pub_key_filename, handle_filename)) {
        printf("Error: error reading in public key files '%s' and '%s'\n", pub_key_filename, handle_filename);
        return -1;
    }

    if (0 != ecp_ZZZ_deserialize(&ctx->public_key, (uint8_t*)ctx->serialized_public_key)) {
        printf("Error: error public key to point\n");
        return -1;
    }

    ctx->tcti_context = (TSS2_TCTI_CONTEXT*)ctx->tcti_buffer;
#ifdef USE_TCP_TPM
    (void)device_conf;
    size_t size;
    ret = Tss2_Tcti_Mssim_Init(NULL, &size, mssim_conf);
    if (TSS2_RC_SUCCESS != ret) {
        printf("Failed to get allocation size for tcti context\n");
        return -1;
    }
    if (size > sizeof(ctx->tcti_buffer)) {
        printf("Error: socket TCTI context size larger than pre-allocated buffer\n");
        return -1;
    }
    ret = Tss2_Tcti_Mssim_Init(ctx->tcti_context, &size, mssim_conf);
    if (TSS2_RC_SUCCESS != ret) {
        printf("Error: Unable to initialize socket TCTI context\n");
        return -1;
    }
#else
    (void)mssim_conf;
    size_t size;
    ret = Tss2_Tcti_Device_Init(NULL, &size, device_conf);
    if (TSS2_RC_SUCCESS != ret) {
        printf("Failed to get allocation size for tcti context\n");
        return -1;
    }
    if (size > sizeof(ctx->tcti_buffer)) {
        printf("Error: device TCTI context size larger than pre-allocated buffer\n");
        return -1;
    }
    ret = Tss2_Tcti_Device_Init(ctx->tcti_context, &size, device_conf);
    if (TSS2_RC_SUCCESS != ret) {
        printf("Error: Unable to initialize device TCTI context\n");
        return -1;
    }
#endif

    ret = ecdaa_tpm_context_init(&ctx->tpm_ctx, key_handle, NULL, 0, ctx->tcti_context);
    if (0 != ret) {
        printf("Error: ecdaa_tpm_context_init failed: 0x%x\n", ret);
        return -1;
    }

    return 0;
}

static
void tpm_cleanup(struct tpm_test_context *ctx)
{
    ecdaa_tpm_context_free(&ctx->tpm_ctx);

    if (NULL != ctx->tcti_context) {
        Tss2_Tcti_Finalize(ctx->tcti_context);
    }
}

int read_public_key_from_files(uint8_t *public_key,
                               TPM2_HANDLE *key_handle,
                               const char *pub_key_filename,
                               const char *handle_filename)
{
    int ret = 0;

    FILE *pub_key_file_ptr = fopen(pub_key_filename, "r");
    if (NULL == pub_key_file_ptr)
        return -1;
    do {
        for (unsigned i=0; i < ECP_ZZZ_LENGTH; i++) {
            unsigned byt;
            if (fscanf(pub_key_file_ptr, "%02X", &byt) != 1) {
                ret = -1;
                break;
            }
            public_key[i] = (uint8_t)byt;
        }
    } while(0);
    (void)fclose(pub_key_file_ptr);
    if (0 != ret)
        return -1;

    FILE *handle_file_ptr = fopen(handle_filename, "r");
    if (NULL == handle_file_ptr)
        return -1;
    do {
        for (int i=(sizeof(TPM2_HANDLE)-1); i >= 0; i--) {
            unsigned byt;
            if (fscanf(handle_file_ptr, "%02X", &byt) != 1) {
                ret = -1;
                break;
            }
            *key_handle += byt<<(i*8);
        }
        if (0 != ret)
            break;
    } while(0);
    (void)fclose(handle_file_ptr);

    return ret;
}
