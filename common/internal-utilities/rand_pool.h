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

#ifndef ECDAA_COMMON_RANDPOOL_H
#define ECDAA_COMMON_RANDPOOL_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

// NOTE: We promise our users that this MUST be <256.
//  This is so getrandom (on Linux) and getentropy (on OpenBSD)
//  can be used as the the source of randomness
#define MAX_RAND_POOL_SIZE 255

struct ecdaa_rand_pool {
    uint8_t pool[MAX_RAND_POOL_SIZE];
    size_t size;
    uint8_t *pool_ptr;
    void (*get_random)(void *buf, size_t buflen);
};

void ecdaa_rand_pool_init(struct ecdaa_rand_pool *pool,
                          size_t requested_size,
                          void (*get_random)(void *buf, size_t buflen));

uint8_t get_random_byte(struct ecdaa_rand_pool *pool);

#ifdef __cplusplus
}
#endif

#endif

