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

#ifndef XAPTUM_ECDAA_EXPLICIT_BZERO_H
#define XAPTUM_ECDAA_EXPLICIT_BZERO_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/*
 * Set memory to 0's, in a way that _shouldn't_ get removed by a compiler
 */
void explicit_bzero(void *const pnt, const size_t len);

#ifdef __cplusplus
}
#endif

#endif
