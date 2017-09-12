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

#include "xaptum-test-utils.h"

#include "../src/amcl-extensions/ecp_BN254.h"

#include <stdio.h>

static void g1_basepoint_not_inf();

int main()
{
    g1_basepoint_not_inf();

    return 0;
}

void g1_basepoint_not_inf()
{
    printf("Starting pairing_curve_utils::g1_basepoint_not_inf...\n");

    ECP_BN254 point;
    ecp_BN254_set_to_generator(&point);

    TEST_ASSERT(!point.inf);

    printf("\tsuccess\n");
}

