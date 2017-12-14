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

#include "src/internal/schnorr_TPM.h"
#include "src/internal/schnorr_FP256BN.h"
#include "src/amcl-extensions/ecp_FP256BN.h"

#include <ecdaa/tpm_context.h>

#include <string.h>

static void full_test();

int main()
{
    full_test();
}

void full_test()
{
    printf("Starting tpm-test::null_point_same_as_generator...\n");

    int ret = 0;

    struct tpm_test_context ctx;
    TEST_ASSERT(0 == tpm_initialize(&ctx));

    ECP_FP256BN G1;
    ecp_FP256BN_set_to_generator(&G1);

    const uint8_t *msg = (uint8_t*)"msg";
    const uint32_t msg_len = 3;

    BIG_256_56 c, s;
    ret = schnorr_sign_TPM(&c,
                           &s,
                           msg,
                           msg_len,
                           &G1,
                           &ctx.tpm_ctx.public_key,
                           &ctx.tpm_ctx);
    if (0 != ret) {
        printf("Error in schnorr_sign_TPM, ret=%d, tpm_rc=0x%x\n", ret, ctx.tpm_ctx.last_return_code);
        TEST_ASSERT(0==1);
    }

    ret = schnorr_verify_FP256BN(c, s, msg, msg_len, &G1, &ctx.tpm_ctx.public_key);
    if (0 != ret) {
        printf("Error in schnorr_verify_TPM, ret=%d, tpm_rc=0x%x\n", ret, ctx.tpm_ctx.last_return_code);
        TEST_ASSERT(0==1);
    }

    tpm_cleanup(&ctx);

    printf("\tsuccess\n");
}
