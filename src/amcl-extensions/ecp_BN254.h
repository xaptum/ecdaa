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

#ifndef ECDAA_ECP_BN254_EXTENSIONS_H
#define ECDAA_ECP_BN254_EXTENSIONS_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <amcl/ecp_BN254.h>

#include <stddef.h>
#include <stdint.h>

#define ECP_BN254_LENGTH (2*MODBYTES_256_56 + 1)
size_t ecp_BN254_length(void);

/*
 * Initialize ECP_BN254 point to G1 generator.
 */
void ecp_BN254_set_to_generator(ECP_BN254 *point);

/*
 * Check if the given ECP_BN254 point is a member of G1.
 *
 * Returns:
 * 0 on success
 * -1 if the point is _not_ in G1
 */
int ecp_BN254_check_membership(ECP_BN254 *point);

/*
 * Serialize an ECP_BN254 point.
 *
 * Format: ( 0x04 | x-coordinate | y-coordinate )
 */
void ecp_BN254_serialize(uint8_t *buffer_out,
                         ECP_BN254 *point);

/*
 * De-serialize an ECP_BN254 point.
 *
 * Format: ( 0x04 | x-coordinate | y-coordinate )
 *
 * Returns:
 * 0 on success
 * -1 if the point is not on the curve
 */
int ecp_BN254_deserialize(ECP_BN254 *point_out,
                          const uint8_t *buffer);

#ifdef __cplusplus
}
#endif

#endif

