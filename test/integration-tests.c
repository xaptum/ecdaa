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

#include <xaptum-ecdaa.h>

#include <stdio.h>
#include <stdint.h>
#include <assert.h>

void basic_test();

int main()
{
    basic_test();

    return 0;
}

void basic_test()
{
    printf("Starting basic_test...\n");

    uint8_t message[] = {0x3, 0x1, 0xa};

    int ret = sign(message);

    assert(ret == 0);

    printf("\tsuccess\n");
}
