/******************************************************************************
 *
 * Copyright 2018 Xaptum, Inc.
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

#if (defined(__linux__))
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/random.h>
#include <errno.h>
#elif defined(__APPLE__)
#include <AvailabilityMacros.h>
#endif

#include "tool_rand.h"

#include <stdlib.h>
#include <stdio.h>

#if (defined(__linux__) && defined(SYS_getrandom))

void tool_rand(void *buf, size_t buflen)
{
    int read_ret = syscall(SYS_getrandom, buf, buflen, 0);
    if (read_ret != (int)buflen) {
        fprintf(stderr, "Error calling getrandom syscall. Ret=%d, errno=%d\n", read_ret, errno);
        exit(1);
    }
}

#elif (defined(__APPLE__) && MAC_OS_X_VERSION_MIN_REQUIRED >= MAC_OS_X_VERSION_10_2)  // previously, used RC4 (biased)

void tool_rand(void *buf, size_t buflen)
{
    // Not worried about chroot or fd-exhaustion issues,
    //  since running this in a short-lived 'tool' executable
    arc4random_buf(buf, buflen);
}

#else

void tool_rand(void *buf, size_t buflen)
{
    // No need to worry about threading, since tool is single-threaded
    static FILE *file_ptr = NULL;
    if (NULL == file_ptr) {
        file_ptr = fopen("/dev/urandom", "r");
        if (file_ptr == NULL) {
            fprintf(stderr, "Error opening /dev/urandom, aborting\n");
            exit(1);
        }
    }

    size_t read_ret = fread(buf, 1, buflen, file_ptr);
    if (read_ret != buflen) {
        fprintf(stderr, "Error reading from /dev/urandom, aborting\n");
        exit(1);
    }
}

#endif
