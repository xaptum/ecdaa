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

#include "../src/pairing_curve_utils.h"

#include <amcl/randapi.h>

#include <stdio.h>
#include <assert.h>

static void g1_basepoint_not_inf();

static void g2_basepoint_not_inf();

static void random_num_mod_order_is_valid();

int main()
{
    g1_basepoint_not_inf();
    g2_basepoint_not_inf();

    random_num_mod_order_is_valid();

    return 0;
}

void g1_basepoint_not_inf()
{
    printf("Starting pairing_curve_utils::g1_basepoint_not_inf...\n");

    ECP_BN254 point;
    set_to_basepoint(&point);

    assert(!point.inf);

    printf("\tsuccess\n");
}

void g2_basepoint_not_inf()
{
    printf("Starting pairing_curve_utils::g2_basepoint_not_inf...\n");

    ECP2_BN254 point;
    set_to_basepoint2(&point);

    assert(!point.inf);

    printf("\tsuccess\n");
}

void random_num_mod_order_is_valid()
{
    printf("Starting random_num_mod_order_is_valid::g2_basepoint_not_inf...\n");

    BIG_256_56 curve_order;
    BIG_256_56_rcopy(curve_order, CURVE_Order_BN254);

    csprng rng;
#define SEED_LEN 256
    char seed_as_bytes[SEED_LEN];
    // TODO Seed
    octet seed = {.len=SEED_LEN, .max=SEED_LEN, .val=seed_as_bytes};
    CREATE_CSPRNG(&rng, &seed);

    BIG_256_56 num;
    for (int i = 0; i < 50000; ++i) {
        random_num_mod_order(&num, &rng);

        assert(BIG_256_56_iszilch(num) == 0);
        assert(BIG_256_56_isunity(num) == 0);

        assert(BIG_256_56_comp(num, curve_order) == -1);
    }

    KILL_CSPRNG(&rng);

    printf("\tsuccess\n");
}
