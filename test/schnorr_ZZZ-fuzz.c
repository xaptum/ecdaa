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

#include "schnorr/schnorr_ZZZ.h"

#include "amcl-extensions/big_XXX.h"
#include "amcl-extensions/ecp_ZZZ.h"
#include "amcl-extensions/ecp2_ZZZ.h"

#include <ecdaa/credential_ZZZ.h>

#include <amcl/big_XXX.h>
#include <amcl/ecp_ZZZ.h>

#include <string.h>
#include <stdio.h>

#define MAX_REPS 10000
#define MAX_MSG_LEN 1024
#define MAX_BASENAME_LEN 1024

static void schnorr_repeated(int schnorr_repetitions);

int main(int argc, char *argv[])
{
    int schnorr_repetitions = 20;
    if (argc == 2) {
        schnorr_repetitions = atoi(argv[1]);
        if (schnorr_repetitions < 1 || schnorr_repetitions > MAX_REPS) {
            fprintf(stderr, "Invalid value '%s' pass to 'repetitions' argument\n", argv[1]);
            return 1;
        }
    }

    schnorr_repeated(schnorr_repetitions);
}

void schnorr_repeated(int schnorr_repetitions)
{
    // The basic Schnorr primitive includes randomness in two places:
    // - in the "commit" stage, and
    // - for the "n" nonce during the "sign" stage

    printf("Starting schnorr::schnorr_repeated...\n");

    uint8_t msg[MAX_MSG_LEN] = {};
    uint32_t msg_len = 0;

    uint8_t basename[MAX_BASENAME_LEN] = {};
    uint32_t basename_len = 0;

    BIG_XXX c, s, n;
    ECP_ZZZ K;

    ECP_ZZZ basepoint;
    ecp_ZZZ_set_to_generator(&basepoint);
    BIG_XXX rand;

    ECP_ZZZ public;
    BIG_XXX private;

    for (int i=0; i<schnorr_repetitions; ++i) {
        // Randomize msg and msg_len
        test_randomness(&msg_len, sizeof(msg_len));
        msg_len = (msg_len % sizeof(msg)) + 1;
        test_randomness(msg, msg_len);

        // Randomize basename and basename_len
        test_randomness(&basename_len, sizeof(basename_len));
        basename_len = (basename_len % sizeof(basename)) + 1;
        test_randomness(basename, basename_len);

        // Randomize basepoint
        ecp_ZZZ_random_mod_order(&rand, test_randomness);
        ECP_ZZZ_mul(&basepoint, rand);

        // Randomize private key
        ecp_ZZZ_random_mod_order(&private, test_randomness);
        ECP_ZZZ_copy(&public, &basepoint);
        ECP_ZZZ_mul(&public, private);

        TEST_ASSERT(0 == schnorr_sign_ZZZ(&c, &s, &n, &K, msg, msg_len, &basepoint, &public, private, basename, basename_len, test_randomness));

        TEST_ASSERT(0 == schnorr_verify_ZZZ(c, s, n, &K, msg, msg_len, &basepoint, &public, basename, basename_len));
    }

    printf("\tsuccess\n");
}
