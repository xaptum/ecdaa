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

#include "src/amcl-extensions/ecp_FP256BN.h"

#include <ecdaa/tpm_context.h>

static
int read_public_key_from_files(ECP_FP256BN *public_key,
                               TPM_HANDLE *key_handle,
                               const char *pub_key_filename,
                               const char *handle_filename);

struct tpm_test_context {
    struct ecdaa_tpm_context tpm_ctx;
};

static
int tpm_initialize(struct tpm_test_context *ctx)
{
    const char *pub_key_filename = "pub_key.txt";
    const char *handle_filename = "handle.txt";
    const char *hostname = "localhost";
    const char *port = "2321";

    int ret = 0;

    ECP_FP256BN public_key;
    TPM_HANDLE key_handle = 0;

    if (0 != read_public_key_from_files(&public_key, &key_handle, pub_key_filename, handle_filename)) {
        printf("Error: error reading in public key files '%s' and '%s'\n", pub_key_filename, handle_filename);
        return -1;
    }

    ret = ecdaa_tpm_context_init_socket(&ctx->tpm_ctx, &public_key, key_handle, hostname, port, NULL, 0);
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
}

int read_public_key_from_files(ECP_FP256BN *public_key,
                               TPM_HANDLE *key_handle,
                               const char *pub_key_filename,
                               const char *handle_filename)
{
    int ret = 0;

    uint8_t public_key_as_bytes[ECP_FP256BN_LENGTH];

    FILE *pub_key_file_ptr = fopen(pub_key_filename, "r");
    if (NULL == pub_key_file_ptr)
        return -1;
    do {
        for (unsigned i=0; i < ECP_FP256BN_LENGTH; i++) {
            unsigned byte;
            if (fscanf(pub_key_file_ptr, "%02X", &byte) != 1) {
                ret = -1;
                break;
            }
            public_key_as_bytes[i] = (uint8_t)byte;
        }
    } while(0);
    (void)fclose(pub_key_file_ptr);
    if (0 != ret)
        return -1;
    if (0 != ecp_FP256BN_deserialize(public_key, public_key_as_bytes))
        return -1;

    FILE *handle_file_ptr = fopen(handle_filename, "r");
    if (NULL == handle_file_ptr)
        return -1;
    do {
        for (int i=(sizeof(TPM_HANDLE)-1); i >= 0; i--) {
            unsigned byte;
            if (fscanf(handle_file_ptr, "%02X", &byte) != 1) {
                ret = -1;
                break;
            }
            *key_handle += byte<<(i*8);
        }
        if (0 != ret)
            break;
    } while(0);
    (void)fclose(handle_file_ptr);

    return ret;
}
