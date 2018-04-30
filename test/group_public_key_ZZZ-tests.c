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

#include <ecdaa/group_public_key_ZZZ.h>

#include "amcl-extensions/ecp2_ZZZ.h"

#include <stdio.h>
#include <string.h>

static void serialize_then_deserialize_basepoints();
static void lengths_same();
static void deserialize_garbage_fails();

int main()
{
    serialize_then_deserialize_basepoints();
    lengths_same();
    deserialize_garbage_fails();

    return 0;
}

static void serialize_then_deserialize_basepoints()
{
    printf("Starting group_public_key::serialize_then_deserialize_basepoints...\n");

    struct ecdaa_group_public_key_ZZZ gpk;

    ecp2_ZZZ_set_to_generator(&gpk.X);
    ecp2_ZZZ_set_to_generator(&gpk.Y);


    uint8_t buffer[ECDAA_GROUP_PUBLIC_KEY_ZZZ_LENGTH];

    ecdaa_group_public_key_ZZZ_serialize(buffer, &gpk);

    struct ecdaa_group_public_key_ZZZ gpk_deserialized;
    TEST_ASSERT(0 == ecdaa_group_public_key_ZZZ_deserialize(&gpk_deserialized, buffer));

    TEST_ASSERT(ECP2_ZZZ_equals(&gpk.X, &gpk_deserialized.X));
    TEST_ASSERT(ECP2_ZZZ_equals(&gpk.Y, &gpk_deserialized.Y));

    printf("\tsuccess\n");
}

static void lengths_same()
{
    printf("Starting group_public_key::lengths_same...\n");

    TEST_ASSERT(ECDAA_GROUP_PUBLIC_KEY_ZZZ_LENGTH == ecdaa_group_public_key_ZZZ_length());

    printf("\tsuccess\n");
}

static void deserialize_garbage_fails()
{
    printf("Starting group_public_key::deserialize_garbage_fails...\n");

    uint8_t buffer[ECDAA_GROUP_PUBLIC_KEY_ZZZ_LENGTH] = {0};
    memset(buffer, 1, sizeof(buffer));  // All 1's
    buffer[0] = 0x4;

    struct ecdaa_group_public_key_ZZZ gpk_deserialized;
    TEST_ASSERT(-1 == ecdaa_group_public_key_ZZZ_deserialize(&gpk_deserialized, buffer));

    printf("\tsuccess\n");
}
