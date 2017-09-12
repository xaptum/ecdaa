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

void get_test_seed(char *out, unsigned out_length)
{
    // Nb. This isn't intended to be secure.
    // It's just for testing.

    srand(time(NULL));
    for (unsigned i = 0; i < out_length; ++i)
        out[i] = rand();
}

void create_test_rng(csprng *rng)
{
    char seed_as_bytes[SEED_LEN];

    get_test_seed(seed_as_bytes, SEED_LEN);

    octet seed = {.len=SEED_LEN, .max=SEED_LEN, .val=seed_as_bytes};

    CREATE_CSPRNG(rng, &seed);
}

void destroy_test_rng(csprng *rng)
{
    KILL_CSPRNG(rng);
}
