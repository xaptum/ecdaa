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
#include "issuer_create_group_ZZZ.h"
#include "tool_rand.h"

#include <ecdaa.h>

int create_group_ZZZ(const char* public_key_file, const char* secret_key_file)
{
    int ret = ecdaa_issuer_key_pair_ZZZ_generate_file(public_key_file, secret_key_file, tool_rand);
    if (0 != ret) {
        return ret;
    }

    return 0;
}
