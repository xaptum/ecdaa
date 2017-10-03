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

#include <ecdaa/prng.h>

#include "internal/explicit_bzero.h"

#ifndef DISABLE_LIBSODIUM_RNG_SEED_FUNCTION

#include <sodium.h>

#if defined(__linux__)
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/random.h>
#endif

static int check_entropy()
{
    int ret = 0;
#if defined(__linux__) && defined(RNDGETENTCNT)
    int fd;
    if ((fd = open("/dev/random", O_RDONLY)) != -1) {
        int c;
        if (ioctl(fd, RNDGETENTCNT, &c) == 0 && c < 160) {
            ret = -2;
        }
        (void) close(fd);
    }
#endif

    return ret;
}

int ecdaa_prng_init(struct ecdaa_prng *prng_in)
{
    int ret = 0;

    prng_in->initialized = ECDAA_PRNG_INITIALIZED_NO;

    do {
        ret = check_entropy();
        if (0 != ret)
            break;

        // Note: We don't have to worry about the race-condition here.
        // `sodium_init` can be called multiple times, and from multiple threads.
        if (-1 == sodium_init()) {
            ret = -1;
            break;
        }

        char seed[AMCL_SEED_SIZE];
        randombytes_buf(seed, sizeof(seed));

        ret = ecdaa_prng_init_custom(prng_in, seed, sizeof(seed));
        if (0 != ret)
            break;
    } while(0);

    if (0 == ret)
        prng_in->initialized = ECDAA_PRNG_INITIALIZED_YES;

    return ret;
}

#endif  // DISABLE_LIBSODIUM_RNG_SEED_FUNCTION

csprng *get_csprng(struct ecdaa_prng *prng)
{
    if (ECDAA_PRNG_INITIALIZED_YES != prng->initialized)
        abort();

    return &prng->impl;
}

void ecdaa_prng_free(struct ecdaa_prng *prng)
{
    explicit_bzero(prng, sizeof(struct ecdaa_prng));

    prng->initialized = ECDAA_PRNG_INITIALIZED_NO;
}

int ecdaa_prng_init_custom(struct ecdaa_prng *prng_in, char *seed, size_t seed_size)
{
    prng_in->initialized = ECDAA_PRNG_INITIALIZED_NO;

    if (AMCL_SEED_SIZE > seed_size) {
        return -1;
    } else if (INT_MAX < seed_size) {
        return -1;
    }

    RAND_seed(&prng_in->impl, (int)seed_size, seed);

    prng_in->initialized = ECDAA_PRNG_INITIALIZED_YES;

    return 0;
}
