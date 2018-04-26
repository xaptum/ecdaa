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

#include "amcl-extensions/ecp2_ZZZ.h"

#include <stdio.h>
#include <string.h>

static void g2_basepoint_not_inf();
static void g2_serialize_then_deserialize_basepoint();
static void g2_lengths_same();
static void g2_deserialize_badformat_fails();
static void g2_deserialize_badcoords_fails();

int main()
{
    g2_basepoint_not_inf();
    g2_serialize_then_deserialize_basepoint();
    g2_lengths_same();
    g2_deserialize_badformat_fails();
    g2_deserialize_badcoords_fails();

    return 0;
}

void g2_basepoint_not_inf()
{
    printf("Starting ecp2_ZZZ::g2_basepoint_not_inf...\n");

    ECP2_ZZZ point;
    ecp2_ZZZ_set_to_generator(&point);

    TEST_ASSERT(!point.inf);

    printf("\tsuccess\n");
}

static void g2_serialize_then_deserialize_basepoint()
{
    printf("Starting ecp2_ZZZ::g2_basepoint_not_inf...\n");

    ECP2_ZZZ point;
    ecp2_ZZZ_set_to_generator(&point);

    uint8_t buffer[ECP2_ZZZ_LENGTH];

    ecp2_ZZZ_serialize(buffer, &point);

    ECP2_ZZZ deserialized_point;
    TEST_ASSERT(0 == ecp2_ZZZ_deserialize(&deserialized_point, buffer));

    TEST_ASSERT(ECP2_ZZZ_equals(&point, &deserialized_point));

    printf("\tsuccess\n");
}

static void g2_lengths_same()
{
    printf("Starting ecp2_ZZZ::g2_lengths_same...\n");

    TEST_ASSERT(ECP2_ZZZ_LENGTH == ecp2_ZZZ_length());

    printf("\tsuccess\n");
}

static void g2_deserialize_badformat_fails()
{
    printf("Starting ecp2_ZZZ::g2_deserialize_badformat_fails...\n");

    uint8_t buffer[ECP2_ZZZ_LENGTH] = {0};
    buffer[0] = 0x3;

    ECP2_ZZZ point;
    TEST_ASSERT(-2 == ecp2_ZZZ_deserialize(&point, buffer));

    printf("\tsuccess\n");
}

static void g2_deserialize_badcoords_fails()
{
    printf("Starting ecp2_ZZZ::g2_deserialize_badcoords_fails...\n");

    uint8_t buffer[ECP2_ZZZ_LENGTH] = {0};
    memset(buffer, 1, sizeof(buffer));  // All 1's
    buffer[0] = 0x4;

    ECP2_ZZZ point;
    TEST_ASSERT(-1 == ecp2_ZZZ_deserialize(&point, buffer));

    printf("\tsuccess\n");
}
