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

#define MAX_MSG_LEN 128
#define MAX_BASENAME_LEN 32

static void schnorr_TPM_repeated(int schnorr_repetitions);

int main(int argc, char *argv[])
{
    int schnorr_repetitions = 5;
    if (argc == 2) {
        schnorr_repetitions = atoi(argv[1]);
    }

    schnorr_TPM_repeated(schnorr_repetitions);
}

void schnorr_TPM_repeated(int schnorr_repetitions)
{
    // The basic Schnorr primitive includes randomness in two places:
    // - in the "commit" stage, and
    // - for the "n" nonce during the "sign" stage

    printf("Starting schnorr_TPM::schnorr_TPM_repeated...\n");

    uint8_t msg[MAX_MSG_LEN] = {};
    uint32_t msg_len = 0;

    uint8_t basename[MAX_BASENAME_LEN] = {};
    uint32_t basename_len = 0;

    BIG_XXX c, s, n;
    ECP_ZZZ K;

    ECP_ZZZ basepoint;
    ecp_ZZZ_set_to_generator(&basepoint);

    struct tpm_test_context ctx;

    for (int i=0; i<schnorr_repetitions; ++i) {
        TEST_ASSERT(0 == tpm_initialize(&ctx));

        // Randomize msg and msg_len
        test_randomness(&msg_len, sizeof(msg_len));
        msg_len = (msg_len % sizeof(msg)) + 1;
        test_randomness(msg, msg_len);

        // Randomize basename and basename_len
        test_randomness(&basename_len, sizeof(basename_len));
        basename_len = (basename_len % sizeof(basename)) + 1;
        test_randomness(basename, basename_len);

        // Note: We can't randomize the basepoint,
        //  since the TPM already used the canonical basepoint for the public key.

        int ret = schnorr_sign_TPM_ZZZ(&c, &s, &n, &K, msg, msg_len, &basepoint, &ctx.public_key, basename, basename_len, &ctx.tpm_ctx);
        if (0 != ret) {
            printf("Error in schnorr_sign_TPM_ZZZ, ret=%d, tpm_rc=0x%x\n", ret, ctx.tpm_ctx.last_return_code);
            TEST_ASSERT(0==1);
        }

        ret = schnorr_verify_ZZZ(c, s, n, &K, msg, msg_len, &basepoint, &ctx.public_key, basename, basename_len);
        if (0 != ret) {
            printf("Error in schnorr_verify_TPM_ZZZ, ret=%d, tpm_rc=0x%x\n", ret, ctx.tpm_ctx.last_return_code);
            TEST_ASSERT(0==1);
        }

        tpm_cleanup(&ctx);
    }

    printf("\tsuccess\n");
}

