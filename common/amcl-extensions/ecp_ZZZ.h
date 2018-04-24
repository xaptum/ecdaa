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

#ifndef ECDAA_ECP_ZZZ_EXTENSIONS_H
#define ECDAA_ECP_ZZZ_EXTENSIONS_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <amcl/ecp_ZZZ.h>

#include <stddef.h>
#include <stdint.h>

#define ECP_ZZZ_LENGTH (2*MODBYTES_XXX + 1)
size_t ecp_ZZZ_length(void);

/*
 * Initialize ECP_ZZZ point to G1 generator.
 */
void ecp_ZZZ_set_to_generator(ECP_ZZZ *point);

/*
 * Serialize an ECP_ZZZ point.
 *
 * Format: ( 0x04 | x-coordinate | y-coordinate )
 */
void ecp_ZZZ_serialize(uint8_t *buffer_out,
                       ECP_ZZZ *point);

/*
 * De-serialize an ECP_ZZZ point.
 *
 * Format: ( 0x04 | x-coordinate | y-coordinate )
 *
 * Returns:
 * 0 on success
 * -1 if the point is not on the curve
 */
int ecp_ZZZ_deserialize(ECP_ZZZ *point_out,
                        uint8_t *buffer);

/*
 * Hash a message into an ECP_ZZZ point.
 *
 * The curve point generated from the message m is found as follows
 *      (cf. "Hunting and Pecking with ECC Groups" in Dragonfly spec):
 *  1. Set i := 0 be a 32-bit unsigned integer.
 *  2. Compute x := H(i, m).
 *  3. Compute z := x**3 + ax + b mod q.
 *  4. Compute y := sqrt(z) mod q. If y does not exist, set i := i + 1,
 *      repeat step 2 if i < 232, otherwise, report failure.
 *  5. Set y to whichever of {y, q - y} has lowest-order bit equal to 0.
 *
 * Returns:
 *  i on success (i is 32-bit unsigned integer used in construction above)
 *  -1 on failure
 */
int32_t ecp_ZZZ_fromhash(ECP_ZZZ *point_out, const uint8_t *message, uint32_t message_length);

/*
 * Generate a uniformly-distributed pseudo-random number,
 * between [0, n], where n is the order of the EC group.
 *
 * Output is normalized.
 */
void ecp_ZZZ_random_mod_order(BIG_XXX *big_out,
                              csprng *rng);

#ifdef __cplusplus
}
#endif

#endif

