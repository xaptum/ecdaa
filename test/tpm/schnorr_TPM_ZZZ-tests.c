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

#include "schnorr-tpm/schnorr_TPM_ZZZ.h"
#include "schnorr/schnorr_FP256BN.h"
#include "amcl-extensions/ecp_FP256BN.h"

#include <ecdaa-tpm/tpm_context.h>

#include <string.h>

static void full_test();
static void schnorr_TPM_basename();
static void schnorr_TPM_wrong_basename_fails();

int main()
{
    full_test();
    schnorr_TPM_basename();
    schnorr_TPM_wrong_basename_fails();
}

void full_test()
{
    printf("Starting tpm-test::full_test...\n");

    int ret = 0;

    struct tpm_test_context ctx;
    TEST_ASSERT(0 == tpm_initialize(&ctx));

    ECP_FP256BN G1;
    ecp_FP256BN_set_to_generator(&G1);

    const uint8_t *msg = (uint8_t*)"msg";
    const uint32_t msg_len = 3;

    BIG_XXX c, s;
    ret = schnorr_sign_TPM_ZZZ(&c,
                               &s,
                               NULL,
                               msg,
                               msg_len,
                               &G1,
                               &ctx.public_key,
                               NULL,
                               0,
                               &ctx.tpm_ctx);
    if (0 != ret) {
        printf("Error in schnorr_sign_TPM_ZZZ, ret=%d, tpm_rc=0x%x\n", ret, ctx.tpm_ctx.last_return_code);
        TEST_ASSERT(0==1);
    }

    ret = schnorr_verify_FP256BN(c, s, NULL, msg, msg_len, &G1, &ctx.public_key, NULL, 0);
    if (0 != ret) {
        printf("Error in schnorr_verify_TPM_ZZZ, ret=%d, tpm_rc=0x%x\n", ret, ctx.tpm_ctx.last_return_code);
        TEST_ASSERT(0==1);
    }

    tpm_cleanup(&ctx);

    printf("\tsuccess\n");
}

static void schnorr_TPM_basename()
{
    printf("Starting schnorr::schnorr_TPM_ZZZ_basename...\n");

    int ret = 0;

    struct tpm_test_context ctx;
    TEST_ASSERT(0 == tpm_initialize(&ctx));

    ECP_FP256BN G1;
    ecp_FP256BN_set_to_generator(&G1);

    uint8_t *msg = (uint8_t*) "Test message";
    uint32_t msg_len = strlen((char*)msg);

    uint8_t *basename = (uint8_t*) "BASENAME";
    uint32_t basename_len = strlen((char*)basename);

    BIG_XXX c, s;
    ECP_FP256BN K;

    ret = schnorr_sign_TPM_ZZZ(&c,
                               &s,
                               &K,
                               msg,
                               msg_len,
                               &G1,
                               &ctx.public_key,
                               basename,
                               basename_len,
                               &ctx.tpm_ctx);
    if (0 != ret) {
        printf("Error in schnorr_sign_TPM_ZZZ, ret=%d, tpm_rc=0x%x\n", ret, ctx.tpm_ctx.last_return_code);
        TEST_ASSERT(0==1);
    }

    TEST_ASSERT(0 == schnorr_verify_FP256BN(c, s, &K, msg, msg_len, &G1, &ctx.public_key, basename, basename_len));

    tpm_cleanup(&ctx);

    printf("\tsuccess\n");
}

static void schnorr_TPM_wrong_basename_fails()
{
    printf("Starting schnorr::schnorr_TPM_ZZZ_wrong_basename_fails...\n");

    int ret = 0;

    struct tpm_test_context ctx;
    TEST_ASSERT(0 == tpm_initialize(&ctx));

    ECP_FP256BN G1;
    ecp_FP256BN_set_to_generator(&G1);

    uint8_t *msg = (uint8_t*) "Test message";
    uint32_t msg_len = strlen((char*)msg);

    uint8_t *basename = (uint8_t*) "BASENAME";
    uint32_t basename_len = strlen((char*)basename);
    uint8_t *wrong_basename = (uint8_t*) "WRONGBASENAME";
    uint32_t wrong_basename_len = strlen((char*)wrong_basename);

    BIG_XXX c, s;
    ECP_FP256BN K;

    ret = schnorr_sign_TPM_ZZZ(&c,
                               &s,
                               &K,
                               msg,
                               msg_len,
                               &G1,
                               &ctx.public_key,
                               basename,
                               basename_len,
                               &ctx.tpm_ctx);
    if (0 != ret) {
        printf("Error in schnorr_sign_TPM_ZZZ, ret=%d, tpm_rc=0x%x\n", ret, ctx.tpm_ctx.last_return_code);
        TEST_ASSERT(0==1);
    }

    TEST_ASSERT(0 != schnorr_verify_FP256BN(c, s, &K, msg, msg_len, &G1, &ctx.public_key, wrong_basename, wrong_basename_len));

    tpm_cleanup(&ctx);

    printf("\tsuccess\n");
}

