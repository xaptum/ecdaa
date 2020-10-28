/******************************************************************************
 *
 * Copyright 2017-2020 Xaptum, Inc.
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

#include "../ecdaa-test-utils.h"
#include "tpm_ZZZ-test-utils.h"

#include <stdlib.h>

static TPMA_SESSION empty_session_attributes = {0};    // attributes for password either can't be set or don't make sense

void parse_cmd_args(int argc, char *argv[]) {
    if (3 != argc) {
        printf("usage: %s <public key output file> <handle output file>\n", argv[0]);
        exit(1);
    }

    pub_key_filename = argv[1];
    handle_filename = argv[2];
    printf("Saving public key to %s and handle to %s\n", pub_key_filename, handle_filename);
}

struct test_context {
    TSS2_SYS_CONTEXT *sapi_ctx;
    TPM2_HANDLE primary_key_handle;
    TPM2_HANDLE signing_key_handle;
    TPM2_HANDLE persistent_key_handle;
    TPM2B_PUBLIC out_public;
    TPM2B_PRIVATE out_private;
    unsigned char tcti_buffer[256];
    unsigned char sapi_buffer[4200];

};

static void initialize(struct test_context *ctx);
static void cleanup(struct test_context *ctx);

static void create_key(const char* pub_key_filename, const char* handle_filename);
static int clear(struct test_context *ctx);
static int create_primary(struct test_context *ctx);
static int create(struct test_context *ctx);
static int load(struct test_context *ctx);
static int save_public_key_info(const struct test_context* ctx, const char* pub_key_filename, const char* handle_filename);
static int evict_control(struct test_context *ctx);

int main(int argc, char *argv[])
{
    // Included in the utils header, but we don't need them.
    (void)tpm_initialize;
    (void)tpm_cleanup;

    parse_cmd_args(argc, argv);

    create_key(pub_key_filename, handle_filename);
}

void initialize(struct test_context *ctx)
{
    const char *mssim_conf = "host=localhost,port=2321";
    const char *device_conf = "/dev/tpm0";

    int init_ret;

    memset(ctx->tcti_buffer, 0, sizeof(ctx->tcti_buffer));
    memset(ctx->sapi_buffer, 0, sizeof(ctx->sapi_buffer));

    TSS2_TCTI_CONTEXT *tcti_ctx = (TSS2_TCTI_CONTEXT*)ctx->tcti_buffer;
#ifdef USE_TCP_TPM
    (void)device_conf;
    size_t size;
    init_ret = Tss2_Tcti_Mssim_Init(NULL, &size, mssim_conf);
    if (TSS2_RC_SUCCESS != init_ret) {
        printf("Error: failed to get allocation size for tcti context\n");
        exit(1);
    }
    if (size > sizeof(ctx->tcti_buffer)) {
        printf("Error: socket TCTI context size larger than pre-allocated buffer\n");
        exit(1);
    }
    init_ret = Tss2_Tcti_Mssim_Init(tcti_ctx, &size, mssim_conf);
    if (TSS2_RC_SUCCESS != init_ret) {
        printf("Error: Unable to initialize socket TCTI context\n");
        exit(1);
    }
#else
    (void)mssim_conf;
    size_t size;
    init_ret = Tss2_Tcti_Device_Init(NULL, &size, device_conf);
    if (TSS2_RC_SUCCESS != init_ret) {
        printf("Failed to get allocation size for tcti context\n");
        exit(1);
    }
    if (size > sizeof(ctx->tcti_buffer)) {
        printf("Error: device TCTI context size larger than pre-allocated buffer\n");
        exit(1);
    }
    init_ret = Tss2_Tcti_Device_Init(tcti_ctx, &size, device_conf);
    if (TSS2_RC_SUCCESS != init_ret) {
        printf("Error: Unable to initialize device TCTI context\n");
        exit(1);
    }
#endif

    ctx->sapi_ctx = (TSS2_SYS_CONTEXT*)ctx->sapi_buffer;
    size_t sapi_ctx_size = Tss2_Sys_GetContextSize(0);
    TEST_ASSERT(sizeof(ctx->sapi_buffer) >= sapi_ctx_size);

    TSS2_ABI_VERSION abi_version = TSS2_ABI_VERSION_CURRENT;
    init_ret = Tss2_Sys_Initialize(ctx->sapi_ctx,
                                   sapi_ctx_size,
                                   tcti_ctx,
                                   &abi_version);
    TEST_ASSERT(TSS2_RC_SUCCESS == init_ret);

    ctx->out_public.size = 0;
    ctx->out_private.size = 0;
}

void cleanup(struct test_context *ctx)
{
    TSS2_TCTI_CONTEXT *tcti_context = NULL;
    TSS2_RC rc;

    if (ctx->sapi_ctx != NULL) {
        rc = Tss2_Sys_GetTctiContext(ctx->sapi_ctx, &tcti_context);
        TEST_ASSERT(TSS2_RC_SUCCESS == rc);

        Tss2_Tcti_Finalize(tcti_context);

        Tss2_Sys_Finalize(ctx->sapi_ctx);
    }
}

void create_key(const char* pub_key_filename, const char* handle_filename)
{
    struct test_context ctx;
    initialize(&ctx);

    int ret = 0;

    ret = clear(&ctx);

    TEST_ASSERT(TSS2_RC_SUCCESS == ret);

    ret = create_primary(&ctx);

    TEST_ASSERT(TSS2_RC_SUCCESS == ret);

    ret = create(&ctx);

    TEST_ASSERT(TSS2_RC_SUCCESS == ret);

    ret = load(&ctx);

    TEST_ASSERT(TSS2_RC_SUCCESS == ret);

    ret = evict_control(&ctx);

    TEST_ASSERT(TSS2_RC_SUCCESS == ret);

    ret = save_public_key_info(&ctx, pub_key_filename, handle_filename);

    TEST_ASSERT(TSS2_RC_SUCCESS == ret);

    cleanup(&ctx);
}

int save_public_key_info(const struct test_context *ctx, const char* pub_key_filename, const char* handle_filename)
{
    int write_ret = 0;

    FILE *pub_key_file_ptr = fopen(pub_key_filename, "w");
    if (NULL == pub_key_file_ptr)
        return -1;
    do {
        if (fprintf(pub_key_file_ptr, "%02X", 4) != 2)
            break;

        for (unsigned i=0; i < ctx->out_public.publicArea.unique.ecc.x.size; i++) {
            if (fprintf(pub_key_file_ptr, "%02X", ctx->out_public.publicArea.unique.ecc.x.buffer[i]) != 2) {
                write_ret = -1;
                break;
            }
        }
        if (0 != write_ret)
            break;

        for (unsigned i=0; i < ctx->out_public.publicArea.unique.ecc.y.size; i++) {
            if (fprintf(pub_key_file_ptr, "%02X", ctx->out_public.publicArea.unique.ecc.y.buffer[i]) != 2) {
                write_ret = -1;
                break;
            }
        }
        if (0 != write_ret)
            break;
    } while(0);
    (void)fclose(pub_key_file_ptr);

    (void)handle_filename;
    FILE *handle_file_ptr = fopen(handle_filename, "w");
    if (NULL == handle_file_ptr)
        return -1;
    write_ret = 0;
    do {
        for (int i=(sizeof(ctx->persistent_key_handle)-1); i >= 0; i--) {
            if (fprintf(handle_file_ptr, "%02X", (ctx->persistent_key_handle >> i*8) & 0xFF) != 2) {
                write_ret = -1;
                break;
            }
        }
        if (0 != write_ret)
            break;
    } while(0);
    (void)fclose(handle_file_ptr);

    return write_ret;
}

int clear(struct test_context *ctx)
{
    TPMI_RH_CLEAR auth_handle = TPM2_RH_LOCKOUT;

    TSS2L_SYS_AUTH_COMMAND sessionsData = {};
    sessionsData.auths[0].sessionHandle = TPM2_RS_PW;
    sessionsData.auths[0].sessionAttributes = empty_session_attributes;
    sessionsData.count = 1;

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {};
    sessionsDataOut.count = 1;

    TSS2_RC ret = Tss2_Sys_Clear(ctx->sapi_ctx,
                                 auth_handle,
                                 &sessionsData,
                                 &sessionsDataOut);

    printf("Clear ret=%#X\n", ret);

    return ret;
}

int create_primary(struct test_context *ctx)
{
    TPMI_RH_HIERARCHY hierarchy = TPM2_RH_ENDORSEMENT;

    TSS2L_SYS_AUTH_COMMAND sessionsData = {};
    sessionsData.auths[0].sessionHandle = TPM2_RS_PW;
    sessionsData.auths[0].sessionAttributes = empty_session_attributes;
    sessionsData.count = 1;

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {};
    sessionsDataOut.count = 1;

    TPM2B_SENSITIVE_CREATE inSensitive = {};

    TPM2B_PUBLIC in_public = {};
    in_public.publicArea.type = TPM2_ALG_ECC;
    in_public.publicArea.nameAlg = TPM2_ALG_SHA256;
    in_public.publicArea.objectAttributes = TPMA_OBJECT_FIXEDTPM |
        TPMA_OBJECT_FIXEDPARENT |
        TPMA_OBJECT_SENSITIVEDATAORIGIN |
        TPMA_OBJECT_USERWITHAUTH |
        TPMA_OBJECT_DECRYPT |
        TPMA_OBJECT_RESTRICTED;
    in_public.publicArea.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_AES;
    in_public.publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
    in_public.publicArea.parameters.eccDetail.symmetric.mode.sym = TPM2_ALG_CFB;
    in_public.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_NULL;
    in_public.publicArea.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
    in_public.publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;

    TPM2B_DATA outsideInfo = {};

    TPML_PCR_SELECTION creationPCR = {};

    TPM2B_CREATION_DATA creationData = {};
    TPM2B_DIGEST creationHash = {};
    TPMT_TK_CREATION creationTicket = {};

    TPM2B_NAME name = {};

    TPM2B_PUBLIC public_key = {};

    TSS2_RC ret = Tss2_Sys_CreatePrimary(ctx->sapi_ctx,
                                        hierarchy,
                                        &sessionsData,
                                        &inSensitive,
                                        &in_public,
                                        &outsideInfo,
                                        &creationPCR,
                                        &ctx->primary_key_handle,
                                        &public_key,
                                        &creationData,
                                        &creationHash,
                                        &creationTicket,
                                        &name,
                                        &sessionsDataOut);

    printf("CreatePrimary ret=%#X\n", ret);

    return ret;
}

int create(struct test_context *ctx)
{
    TSS2L_SYS_AUTH_COMMAND sessionsData = {};
    sessionsData.auths[0].sessionHandle = TPM2_RS_PW;
    sessionsData.auths[0].sessionAttributes = empty_session_attributes;
    sessionsData.count = 1;

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {};
    sessionsDataOut.count = 1;

    TPM2B_SENSITIVE_CREATE inSensitive = {};

    TPM2B_PUBLIC in_public = {};
    in_public.publicArea.type = TPM2_ALG_ECC;
    in_public.publicArea.nameAlg = TPM2_ALG_SHA256;
    in_public.publicArea.objectAttributes = TPMA_OBJECT_FIXEDTPM |
        TPMA_OBJECT_FIXEDPARENT |
        TPMA_OBJECT_SENSITIVEDATAORIGIN |
        TPMA_OBJECT_USERWITHAUTH |
        TPMA_OBJECT_SIGN_ENCRYPT;
    in_public.publicArea.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_NULL;
    in_public.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_ECDAA;
    in_public.publicArea.parameters.eccDetail.scheme.details.ecdaa.hashAlg = TPM2_ALG_SHA256;
    in_public.publicArea.parameters.eccDetail.scheme.details.ecdaa.count = 1;
    in_public.publicArea.parameters.eccDetail.curveID = TPM2_ECC_BN_P256;
    in_public.publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;

    TPM2B_DATA outsideInfo = {};

    TPML_PCR_SELECTION creationPCR = {};

    TPM2B_CREATION_DATA creationData = {};
    TPM2B_DIGEST creationHash = {};
    TPMT_TK_CREATION creationTicket = {};

    TSS2_RC ret = Tss2_Sys_Create(ctx->sapi_ctx,
                                  ctx->primary_key_handle,
                                  &sessionsData,
                                  &inSensitive,
                                  &in_public,
                                  &outsideInfo,
                                  &creationPCR,
                                  &ctx->out_private,
                                  &ctx->out_public,
                                  &creationData,
                                  &creationHash,
                                  &creationTicket,
                                  &sessionsDataOut);

    printf("Create ret=%#X\n", ret);

    return ret;
}

int load(struct test_context *ctx)
{
    TSS2L_SYS_AUTH_COMMAND sessionsData = {};
    sessionsData.auths[0].sessionHandle = TPM2_RS_PW;
    sessionsData.auths[0].sessionAttributes = empty_session_attributes;
    sessionsData.count = 1;

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {};
    sessionsDataOut.count = 1;

    TPM2B_NAME name = {};

    int ret = Tss2_Sys_Load(ctx->sapi_ctx,
                            ctx->primary_key_handle,
                            &sessionsData,
                            &ctx->out_private,
                            &ctx->out_public,
                            &ctx->signing_key_handle,
                            &name,
                            &sessionsDataOut);

    printf("Load ret=%#X\n", ret);

    return ret;
}

int evict_control(struct test_context *ctx)
{
    TSS2L_SYS_AUTH_COMMAND sessionsData = {};
    sessionsData.auths[0].sessionHandle = TPM2_RS_PW;
    sessionsData.auths[0].sessionAttributes = empty_session_attributes;
    sessionsData.count = 1;

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {};
    sessionsDataOut.count = 1;

    ctx->persistent_key_handle = 0x81010000;

    TSS2_RC ret = Tss2_Sys_EvictControl(ctx->sapi_ctx,
                                        TPM2_RH_OWNER,
                                        ctx->signing_key_handle,
                                        &sessionsData,
                                        ctx->persistent_key_handle,
                                        &sessionsDataOut);

    printf("EvictControl ret=%#X\n", ret);

    return ret;
}
