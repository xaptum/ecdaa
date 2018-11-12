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

#include <ecdaa-tpm/tpm_context.h>

#include "amcl-extensions/big_XXX.h"
#include "amcl-extensions/ecp_ZZZ.h"
#include "tpm/commit_ZZZ.h"
#include "tpm/sign.h"

#include <string.h>
#include <stdio.h>

static void signature_math_checks();

int main()
{
    signature_math_checks();
}

void signature_math_checks()
{
    int ret = 0;

    struct tpm_test_context ctx;
    TEST_ASSERT(0 == tpm_initialize(&ctx));

    // Commit
    ECP_ZZZ K, L, E;
    ECP_ZZZ G1;
    ecp_ZZZ_set_to_generator(&G1);
    ret = tpm_commit_ZZZ(&ctx.tpm_ctx, &G1, NULL, 0, &K, &L, &E);
    if (0 != ret) {
        printf("Error: Tss2_Sys_Commit failed: 0x%x, ret=%d\n", ctx.tpm_ctx.last_return_code, ret);
        TEST_ASSERT(0 == ret);
    }
    printf("Called TPM2_Commit with empty buffers, now count=%d, and \nE:{", ctx.tpm_ctx.commit_counter);
    uint8_t e_buf[ECP_ZZZ_LENGTH];
    ecp_ZZZ_serialize(e_buf, &E);
    for (int i = 0; i < ECP_ZZZ_LENGTH; i++) {
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
    BIG_XXX s;
    BIG_XXX_fromBytes(s, (char*)signature.signature.ecdaa.signatureS.buffer);

    // Check that s is a valid finite-field element (just in case).
    BIG_XXX curve_order;
    BIG_XXX_rcopy(curve_order, CURVE_Order_ZZZ);
    if (BIG_XXX_comp(s, curve_order) > 0) {
        printf("\ns > curve_order!!\n");
        TEST_ASSERT(0 == 1);
    }

    // Calculate T = Hash(k || c)
    BIG_XXX T;
    big_XXX_from_two_message_hash(&T,
            signature.signature.ecdaa.signatureR.buffer,
            signature.signature.ecdaa.signatureR.size,
            digest.buffer,
            digest.size);

    // Calculate [s]G - [T]pub_key
    // This should equal E
    ECP_ZZZ_mul(&G1, s);
    ECP_ZZZ_mul(&ctx.public_key, T);
    ECP_ZZZ_sub(&G1, &ctx.public_key);
    ECP_ZZZ_affine(&G1);
    printf("[s]G1 - c*pub_key={");
    uint8_t g1_buf[ECP_ZZZ_LENGTH];
    ecp_ZZZ_serialize(g1_buf, &G1);
    for (int i = 0; i < ECP_ZZZ_LENGTH; i++) {
        printf("%#X, ", g1_buf[i]);
    }
    printf("}\n\n");
    fflush(stdout);

    if (!ECP_ZZZ_equals(&G1, &E)) {
        printf("Error: [s]G1 - T*pub_key != E\n");
        TEST_ASSERT(0 == 1);
    }

    tpm_cleanup(&ctx);

    printf("\tsuccess\n");
}
