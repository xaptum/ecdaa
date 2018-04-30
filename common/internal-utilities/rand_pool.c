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

#include "rand_pool.h"

void ecdaa_rand_pool_init(struct ecdaa_rand_pool *pool,
                          size_t requested_size,
                          void (*get_random)(void *buf, size_t buflen))
{
    // Fill our pool with randomness (will be replenished if needed)
    pool->size = requested_size>sizeof(pool->pool) ? sizeof(pool->pool) : requested_size;
    get_random(pool->pool, pool->size);
    pool->pool_ptr = pool->pool;
    pool->get_random = get_random;
}

uint8_t get_random_byte(struct ecdaa_rand_pool *pool)
{
    if (pool->pool_ptr >= (pool->pool + pool->size)) {
        pool->get_random(pool->pool, pool->size);
        pool->pool_ptr = pool->pool;
    }

    pool->pool_ptr += 1;
    return *(pool->pool_ptr - 1);
}

