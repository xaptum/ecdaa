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

#include "../ecdaa-test-utils.h"
#include "tpm_ZZZ-test-utils.h"

#include <stdlib.h>

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
    TPM_HANDLE primary_key_handle;
    TPM_HANDLE signing_key_handle;
    TPM_HANDLE persistent_key_handle;
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
    const char *hostname = "localhost";
    const char *port = "2321";
    const char *dev_filepath = "/dev/tpm0";

    int init_ret;

    TSS2_TCTI_CONTEXT *tcti_ctx = (TSS2_TCTI_CONTEXT*)ctx->tcti_buffer;
#ifdef USE_TCP_TPM
    (void)dev_filepath;
    if (tss2_tcti_getsize_socket() > sizeof(ctx->tcti_buffer)) {
        printf("Error: socket TCTI context size larger than pre-allocated buffer\n");
        exit(1);
    }
    init_ret = tss2_tcti_init_socket(hostname, port, tcti_ctx);
    if (TSS2_RC_SUCCESS != init_ret) {
        printf("Error: Unable to initialize socket TCTI context\n");
        exit(1);
    }
#else
    (void)hostname;
    (void)port;
    if (tss2_tcti_getsize_device() > sizeof(ctx->tcti_buffer)) {
        printf("Error: device TCTI context size larger than pre-allocated buffer\n");
        exit(1);
    }
    init_ret = tss2_tcti_init_device(dev_filepath, strlen(dev_filepath), tcti_ctx);
    if (TSS2_RC_SUCCESS != init_ret) {
        printf("Error: Unable to initialize device TCTI context\n");
        exit(1);
    }
#endif

    ctx->sapi_ctx = (TSS2_SYS_CONTEXT*)ctx->sapi_buffer;
    size_t sapi_ctx_size = Tss2_Sys_GetContextSize(0);
    TEST_ASSERT(sizeof(ctx->sapi_buffer) >= sapi_ctx_size);

    TSS2_ABI_VERSION abi_version = TSS2_ABI_CURRENT_VERSION;
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

        tss2_tcti_finalize(tcti_context);

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
   TPMI_RH_CLEAR auth_handle = TPM_RH_PLATFORM;

    TPMS_AUTH_COMMAND session_data = {
        .sessionHandle = TPM_RS_PW,
        .sessionAttributes = {0},
    };
    TPMS_AUTH_RESPONSE sessionDataOut = {{0}, {0}, {0}};
    (void)sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPMS_AUTH_COMMAND *sessionDataArray[1];
    sessionDataArray[0] = &session_data;
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];
    sessionDataOutArray[0] = &sessionDataOut;
    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];
    sessionsDataOut.rspAuthsCount = 1;
    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &session_data;

    TSS2_RC ret = Tss2_Sys_Clear(ctx->sapi_ctx,
                                 auth_handle,
                                 &sessionsData,
                                 &sessionsDataOut);

    printf("Clear ret=%#X\n", ret);

    return ret;
}

int create_primary(struct test_context *ctx)
{
    TPMI_RH_HIERARCHY hierarchy = TPM_RH_ENDORSEMENT;

    TPMS_AUTH_COMMAND session_data = {
        .sessionHandle = TPM_RS_PW,
        .sessionAttributes = {0},
    };
    TPMS_AUTH_RESPONSE sessionDataOut = {{0}, {0}, {0}};
    (void)sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPMS_AUTH_COMMAND *sessionDataArray[1];
    sessionDataArray[0] = &session_data;
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];
    sessionDataOutArray[0] = &sessionDataOut;
    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];
    sessionsDataOut.rspAuthsCount = 1;
    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &session_data;

    TPM2B_SENSITIVE_CREATE inSensitive = {.sensitive={.data.size = 0,
                                                      .userAuth.size = 0}};

    TPMA_OBJECT obj_attrs = {.fixedTPM=1, .fixedParent=1, .sensitiveDataOrigin=1, .userWithAuth=1, .decrypt=1, .restricted=1, .sign=0};
    TPM2B_PUBLIC in_public = {.publicArea = {.type=TPM_ALG_ECC,
                                             .nameAlg=TPM_ALG_SHA256,
                                             .objectAttributes=obj_attrs}};
    in_public.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_AES;
    in_public.publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
    in_public.publicArea.parameters.eccDetail.symmetric.mode.sym = TPM_ALG_CFB;
    in_public.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
    in_public.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
    in_public.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
    in_public.publicArea.unique.ecc.x.size = 0;
    in_public.publicArea.unique.ecc.y.size = 0;

    TPM2B_DATA outsideInfo = {.size=0};

    TPML_PCR_SELECTION creationPCR = {.count=0};

    TPM2B_CREATION_DATA creationData = {.size=0};
    TPM2B_DIGEST creationHash = {.size=sizeof(TPMU_HA)};
    TPMT_TK_CREATION creationTicket = {.tag=0,
		                               .hierarchy=0,
		                               .digest={.size=0}};

    TPM2B_NAME name = {.size=sizeof(TPMU_NAME)};

    TPM2B_PUBLIC public_key;

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
    TPMS_AUTH_COMMAND session_data = {
        .sessionHandle = TPM_RS_PW,
        .sessionAttributes = {0},
    };
    TPMS_AUTH_RESPONSE sessionDataOut = {{0}, {0}, {0}};
    (void)sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPMS_AUTH_COMMAND *sessionDataArray[1];
    sessionDataArray[0] = &session_data;
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];
    sessionDataOutArray[0] = &sessionDataOut;
    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];
    sessionsDataOut.rspAuthsCount = 1;
    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &session_data;

    TPM2B_SENSITIVE_CREATE inSensitive = {.sensitive={.data.size = 0,
                                                      .userAuth.size = 0}};

    TPMA_OBJECT obj_attrs = {.fixedTPM=1, .fixedParent=1, .sensitiveDataOrigin=1, .userWithAuth=1, .sign=1};
    TPM2B_PUBLIC in_public = {.publicArea = {.type=TPM_ALG_ECC,
                                             .nameAlg=TPM_ALG_SHA256,
                                             .objectAttributes=obj_attrs}};
    in_public.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
    in_public.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_ECDAA;
    in_public.publicArea.parameters.eccDetail.scheme.details.ecdaa.hashAlg = TPM_ALG_SHA256;
    in_public.publicArea.parameters.eccDetail.scheme.details.ecdaa.count = 1;
    in_public.publicArea.parameters.eccDetail.curveID = TPM_ECC_BN_P256;
    in_public.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
    in_public.publicArea.unique.ecc.x.size = 0;
    in_public.publicArea.unique.ecc.y.size = 0;


    TPM2B_DATA outsideInfo = {.size=0};

    TPML_PCR_SELECTION creationPCR = {.count=0};

    TPM2B_CREATION_DATA creationData = {.size=0};
    TPM2B_DIGEST creationHash = {.size=sizeof(TPMU_HA)};
    TPMT_TK_CREATION creationTicket = {.tag=0,
		                               .hierarchy=0,
		                               .digest={.size=0}};

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
    TPMS_AUTH_COMMAND session_data = {
        .sessionHandle = TPM_RS_PW,
        .sessionAttributes = {0},
    };
    TPMS_AUTH_RESPONSE sessionDataOut = {{0}, {0}, {0}};
    (void)sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPMS_AUTH_COMMAND *sessionDataArray[1];
    sessionDataArray[0] = &session_data;
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];
    sessionDataOutArray[0] = &sessionDataOut;
    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];
    sessionsDataOut.rspAuthsCount = 1;
    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &session_data;

    TPM2B_NAME name = {.size=sizeof(TPMU_NAME)};

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
    TPMS_AUTH_COMMAND session_data = {
        .sessionHandle = TPM_RS_PW,
        .sessionAttributes = {0},
    };
    TPMS_AUTH_RESPONSE sessionDataOut = {{0}, {0}, {0}};
    (void)sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPMS_AUTH_COMMAND *sessionDataArray[1];
    sessionDataArray[0] = &session_data;
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];
    sessionDataOutArray[0] = &sessionDataOut;
    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];
    sessionsDataOut.rspAuthsCount = 1;
    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &session_data;


    ctx->persistent_key_handle = 0x81010000;

    TSS2_RC ret = Tss2_Sys_EvictControl(ctx->sapi_ctx,
                                        TPM_RH_OWNER,
                                        ctx->signing_key_handle,
                                        &sessionsData,
                                        ctx->persistent_key_handle,
                                        &sessionsDataOut);

    printf("EvictControl ret=%#X\n", ret);

    return ret;
}
