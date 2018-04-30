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

#include "amcl-extensions/ecp_ZZZ.h"

#include <stdio.h>
#include <string.h>

static void g1_basepoint_not_inf();
static void g1_serialize_then_deserialize_basepoint();
static void g1_lengths_same();
static void g1_deserialize_badformat_fails();
static void g1_deserialize_badcoords_fails();
static void random_num_mod_order_is_valid();

int main()
{
    g1_basepoint_not_inf();
    g1_serialize_then_deserialize_basepoint();
    g1_lengths_same();
    g1_deserialize_badformat_fails();
    g1_deserialize_badcoords_fails();
    random_num_mod_order_is_valid();

    return 0;
}

void g1_basepoint_not_inf()
{
    printf("Starting ecp_ZZZ::g1_basepoint_not_inf...\n");

    ECP_ZZZ point;
    ecp_ZZZ_set_to_generator(&point);

    TEST_ASSERT(!point.inf);

    printf("\tsuccess\n");
}

static void g1_serialize_then_deserialize_basepoint()
{
    printf("Starting ecp_ZZZ::g1_serialize_then_deserialize_basepoint...\n");

    ECP_ZZZ point;
    ecp_ZZZ_set_to_generator(&point);

    uint8_t buffer[ECP_ZZZ_LENGTH];

    ecp_ZZZ_serialize(buffer, &point);

    ECP_ZZZ deserialized_point;
    TEST_ASSERT(0 == ecp_ZZZ_deserialize(&deserialized_point, buffer));

    TEST_ASSERT(ECP_ZZZ_equals(&point, &deserialized_point));

    printf("\tsuccess\n");
}

static void g1_lengths_same()
{
    printf("Starting ecp_ZZZ::g1_lengths_same...\n");

    TEST_ASSERT(ECP_ZZZ_LENGTH == ecp_ZZZ_length());

    printf("\tsuccess\n");
}

static void g1_deserialize_badformat_fails()
{
    printf("Starting ecp_ZZZ::g1_deserialize_badformat_fails...\n");

    uint8_t buffer[ECP_ZZZ_LENGTH] = {0};
    buffer[0] = 0x3;

    ECP_ZZZ point;
    TEST_ASSERT(-2 == ecp_ZZZ_deserialize(&point, buffer));

    printf("\tsuccess\n");
}

static void g1_deserialize_badcoords_fails()
{
    printf("Starting ecp_ZZZ::g1_deserialize_badcoords_fails...\n");

    uint8_t buffer[ECP_ZZZ_LENGTH] = {0};
    memset(buffer, 1, sizeof(buffer));  // All 1's
    buffer[0] = 0x4;

    ECP_ZZZ point;
    TEST_ASSERT(-1 == ecp_ZZZ_deserialize(&point, buffer));

    printf("\tsuccess\n");
}

void random_num_mod_order_is_valid()
{
    printf("Starting pairing_curve_utils::random_num_mod_order_is_valid...\n");

    BIG_XXX curve_order;
    BIG_XXX_rcopy(curve_order, CURVE_Order_ZZZ);

    BIG_XXX num;
    BIG_XXX prev_num;
    BIG_XXX_one(prev_num);
    for (int i = 0; i < 50000; ++i) {
        ecp_ZZZ_random_mod_order(&num, test_randomness);

        TEST_ASSERT(BIG_XXX_iszilch(num) == 0);
        TEST_ASSERT(BIG_XXX_isunity(num) == 0);

        TEST_ASSERT(BIG_XXX_comp(num, curve_order) == -1);

        TEST_ASSERT(BIG_XXX_comp(num, prev_num) != 0);
        BIG_XXX_copy(prev_num, num);
    }

    printf("\tsuccess\n");
}
