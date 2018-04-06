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

#include "ecdaa-test-utils.h"
#include "tpm-test-utils.h"

#include <ecdaa/tpm_context.h>
#include <ecdaa/prng.h>
#include "src/amcl-extensions/big_XXX.h"
#include "src/amcl-extensions/ecp_FP256BN.h"

#include "src/tpm-utils/commit.h"
#include "src/tpm-utils/sign.h"

#include <string.h>
#include <stdio.h>

static void null_point_same_as_generator();
static void zero_hash_returns_commitment();
static void commit_with_s2();
static void one_hash_returns_commitment_plus_priv_key();

int main()
{
    null_point_same_as_generator();
    zero_hash_returns_commitment();
    commit_with_s2();
    one_hash_returns_commitment_plus_priv_key();
}

void null_point_same_as_generator()
{
    int ret = 0;

    printf("Starting tpm-test::null_point_same_as_generator...\n");

    struct tpm_test_context ctx;
    TEST_ASSERT(0 == tpm_initialize(&ctx));

    // Commit
    ECP_FP256BN K, L, E;
    ECP_FP256BN G1;
    ecp_FP256BN_set_to_generator(&G1);
    ret = tpm_commit(&ctx.tpm_ctx, NULL, NULL, 0, &K, &L, &E);
    if (0 != ret) {
        printf("Error: Tss2_Sys_Commit failed: 0x%x, ret=%d\n", ctx.tpm_ctx.last_return_code, ret);
        TEST_ASSERT(0 == ret);
    }
    printf("Called TPM2_Commit with empty buffers, now count=%d, and \nE:{", ctx.tpm_ctx.commit_counter);
    uint8_t e_buf[ECP_FP256BN_LENGTH];
    ecp_FP256BN_serialize(e_buf, &E);
    for (int i = 0; i < ECP_FP256BN_LENGTH; i++) {
        printf("%#X, ", e_buf[i]);
    }
    printf("}\n\n");
    fflush(stdout);

    // Nb. digest == 0
    TPM2B_DIGEST digest = {.size=32, .buffer={0}};

    // Sign
    TPMT_SIGNATURE signature;
    ret = tpm_sign(&ctx.tpm_ctx, &digest, &signature);
    if (0 != ret) {
        printf("Error: Tss2_Sign failed: 0x%x\n", ctx.tpm_ctx.last_return_code);
        TEST_ASSERT(0 == ret);
    }
    printf("Called TPM2_Sign with a zero hash, and \ns:{");

    BIG_XXX s;
    BIG_XXX_fromBytes(s, (char*)signature.signature.ecdaa.signatureS.buffer);

    uint8_t s_buf[MODBYTES_XXX];
    BIG_XXX_toBytes((char*)s_buf, s);
    for (int i = 0; i < MODBYTES_XXX; i++) {
        printf("%#X, ", s_buf[i]);
    }
    printf("}\n\n");
    fflush(stdout);

    ECP_FP256BN_mul(&G1, s);
    printf("[s]G1={");
    uint8_t g1_buf[ECP_FP256BN_LENGTH];
    ecp_FP256BN_serialize(g1_buf, &G1);
    for (int i = 0; i < ECP_FP256BN_LENGTH; i++) {
        printf("%#X, ", g1_buf[i]);
    }
    printf("}\n\n");
    fflush(stdout);

    TEST_ASSERT(ECP_FP256BN_equals(&G1, &E));

    tpm_cleanup(&ctx);

    printf("\tsuccess\n");
}

void commit_with_s2()
{
    int ret = 0;

    printf("Starting tpm-test::commit_with_s2...\n");

    struct tpm_test_context ctx;
    TEST_ASSERT(0 == tpm_initialize(&ctx));

    ECP_FP256BN G1;
    ecp_FP256BN_set_to_generator(&G1);

    // Commit
    ECP_FP256BN K, L, E;
    uint8_t *message = (uint8_t*)"test message";
    uint32_t message_length = strlen((char*)message);
    ret = tpm_commit(&ctx.tpm_ctx, &G1, message, message_length, &K, &L, &E);
    if (0 != ret) {
        printf("Error: Tss2_Sys_Commit failed: 0x%x, ret=%d\n", ctx.tpm_ctx.last_return_code, ret);
        TEST_ASSERT(0 == ret);
    }
    printf("Called TPM2_Commit with non-empty s2, now count=%d, \nK:{", ctx.tpm_ctx.commit_counter);
    uint8_t k_buf[ECP_FP256BN_LENGTH];
    ecp_FP256BN_serialize(k_buf, &K);
    for (int i = 0; i < ECP_FP256BN_LENGTH; i++) {
        printf("%#X, ", k_buf[i]);
    }
    printf("}\nL:");
    uint8_t l_buf[ECP_FP256BN_LENGTH];
    ecp_FP256BN_serialize(l_buf, &L);
    for (int i = 0; i < ECP_FP256BN_LENGTH; i++) {
        printf("%#X, ", l_buf[i]);
    }
    printf("}\nE:");
    uint8_t e_buf[ECP_FP256BN_LENGTH];
    ecp_FP256BN_serialize(e_buf, &E);
    for (int i = 0; i < ECP_FP256BN_LENGTH; i++) {
        printf("%#X, ", e_buf[i]);
    }
    printf("}\n\n");
    fflush(stdout);

    tpm_cleanup(&ctx);

    printf("\tsuccess\n");
}

void zero_hash_returns_commitment()
{
    printf("Starting tpm-test::zero_hash_returns_commitment...\n");

    int ret = 0;

    struct tpm_test_context ctx;
    TEST_ASSERT(0 == tpm_initialize(&ctx));

    // Commit
    ECP_FP256BN K, L, E;
    ECP_FP256BN G1;
    ecp_FP256BN_set_to_generator(&G1);
    struct ecdaa_prng prng;
    TEST_ASSERT(0 == ecdaa_prng_init(&prng));
    BIG_XXX exp;
    ecp_FP256BN_random_mod_order(&exp, get_csprng(&prng));
    ECP_FP256BN_mul(&G1, exp);
    ret = tpm_commit(&ctx.tpm_ctx, &G1, NULL, 0, &K, &L, &E);
    if (0 != ret) {
        printf("Error: Tss2_Sys_Commit failed: 0x%x, ret=%d\n", ctx.tpm_ctx.last_return_code, ret);
        TEST_ASSERT(0 == ret);
    }
    printf("Called TPM2_Commit with empty buffers, now count=%d, and \nE:{", ctx.tpm_ctx.commit_counter);
    uint8_t e_buf[ECP_FP256BN_LENGTH];
    ecp_FP256BN_serialize(e_buf, &E);
    for (int i = 0; i < ECP_FP256BN_LENGTH; i++) {
        printf("%#X, ", e_buf[i]);
    }
    printf("}\n\n");
    fflush(stdout);

    // Nb. digest == 0
    TPM2B_DIGEST digest = {.size=32, .buffer={0}};

    // Sign
    TPMT_SIGNATURE signature;
    ret = tpm_sign(&ctx.tpm_ctx, &digest, &signature);
    if (0 != ret) {
        printf("Error: Tss2_Sign failed: 0x%x\n", ctx.tpm_ctx.last_return_code);
        TEST_ASSERT(0 == ret);
    }
    printf("Called TPM2_Sign with a zero hash, and \ns:{");

    BIG_XXX s;
    BIG_XXX_fromBytes(s, (char*)signature.signature.ecdaa.signatureS.buffer);

    uint8_t s_buf[MODBYTES_XXX];
    BIG_XXX_toBytes((char*)s_buf, s);
    for (int i = 0; i < MODBYTES_XXX; i++) {
        printf("%#X, ", s_buf[i]);
    }
    printf("}\n\n");
    fflush(stdout);

    ECP_FP256BN_mul(&G1, s);
    printf("[s]G1={");
    uint8_t g1_buf[ECP_FP256BN_LENGTH];
    ecp_FP256BN_serialize(g1_buf, &G1);
    for (int i = 0; i < ECP_FP256BN_LENGTH; i++) {
        printf("%#X, ", g1_buf[i]);
    }
    printf("}\n\n");
    fflush(stdout);

    TEST_ASSERT(ECP_FP256BN_equals(&G1, &E));

    tpm_cleanup(&ctx);

    printf("\tsuccess\n");
}

void one_hash_returns_commitment_plus_priv_key()
{
    int ret = 0;

    struct tpm_test_context ctx;
    TEST_ASSERT(0 == tpm_initialize(&ctx));

    // Commit
    ECP_FP256BN K, L, E;
    ECP_FP256BN G1;
    ecp_FP256BN_set_to_generator(&G1);
    ret = tpm_commit(&ctx.tpm_ctx, NULL, NULL, 0, &K, &L, &E);
    if (0 != ret) {
        printf("Error: Tss2_Sys_Commit failed: 0x%x, ret=%d\n", ctx.tpm_ctx.last_return_code, ret);
        TEST_ASSERT(0 == ret);
    }
    printf("Called TPM2_Commit with empty buffers, now count=%d, and \nE:{", ctx.tpm_ctx.commit_counter);
    uint8_t e_buf[ECP_FP256BN_LENGTH];
    ecp_FP256BN_serialize(e_buf, &E);
    for (int i = 0; i < ECP_FP256BN_LENGTH; i++) {
        printf("%#X, ", e_buf[i]);
    }
    printf("}\n\n");
    fflush(stdout);

    // Nb. digest == 1
    BIG_XXX one;
    BIG_XXX_one(one);
    TPM2B_DIGEST digest = {.size=32, .buffer={0}};
    BIG_XXX_toBytes((char*)digest.buffer, one);

    // Sign
    TPMT_SIGNATURE signature;
    ret = tpm_sign(&ctx.tpm_ctx, &digest, &signature);
    if (0 != ret) {
        printf("Error: Tss2_Sign failed: 0x%x\n", ctx.tpm_ctx.last_return_code);
        TEST_ASSERT(0 == ret);
    }

    BIG_XXX s;
    BIG_XXX_fromBytes(s, (char*)signature.signature.ecdaa.signatureS.buffer);
    BIG_XXX c;
    BIG_XXX_fromBytes(c, (char*)signature.signature.ecdaa.signatureR.buffer);

    BIG_XXX curve_order;
    BIG_XXX_rcopy(curve_order, CURVE_Order_FP256BN);
    if (BIG_XXX_comp(s, curve_order) > 0) {
        printf("\ns > curve_order!!\n");
        TEST_ASSERT(0 == 1);
    }

    printf("Called TPM2_Sign with a one hash, and \nc:{");
    uint8_t c_buf[MODBYTES_XXX];
    BIG_XXX_toBytes((char*)c_buf, c);
    for (int i = 0; i < MODBYTES_XXX; i++) {
        printf("%#X, ", c_buf[i]);
    }
    printf("}\n\ns:{");
    fflush(stdout);
    uint8_t s_buf[MODBYTES_XXX];
    BIG_XXX_toBytes((char*)s_buf, s);
    for (int i = 0; i < MODBYTES_XXX; i++) {
        printf("%#X, ", s_buf[i]);
    }
    printf("}\n\n");
    fflush(stdout);

    ECP_FP256BN_mul(&G1, s);
    ECP_FP256BN_mul(&ctx.public_key, c);
    ECP_FP256BN_sub(&G1, &ctx.public_key);
    ECP_FP256BN_affine(&G1);
    printf("[s]G1 - c*pub_key={");
    uint8_t g1_buf[ECP_FP256BN_LENGTH];
    ecp_FP256BN_serialize(g1_buf, &G1);
    for (int i = 0; i < ECP_FP256BN_LENGTH; i++) {
        printf("%#X, ", g1_buf[i]);
    }
    printf("}\n\n");
    fflush(stdout);

    if (!ECP_FP256BN_equals(&G1, &E)) {
        printf("Error: [s]G1 - c*pub_key != E\n");
        TEST_ASSERT(0 == 1);
    }

    tpm_cleanup(&ctx);

    printf("\tsuccess\n");
}
