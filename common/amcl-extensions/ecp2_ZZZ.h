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

#ifndef ECDAA_ECP2_ZZZ_EXTENSIONS_H
#define ECDAA_ECP2_ZZZ_EXTENSIONS_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <amcl/include/ecp2_ZZZ.h>

#include <stddef.h>

#define ECP2_ZZZ_LENGTH (4*MODBYTES_XXX + 1)
size_t ecp2_ZZZ_length(void);

/*
 * Initialize ECP2_ZZZ point to G2 generator.
 */
void ecp2_ZZZ_set_to_generator(ECP2_ZZZ *point);

/*
 * Serialize an ECP2_ZZZ point.
 *
 * Format: ( 0x04 | x-coordinate-real-part | x-coordinate-imaginary-part | y-coordinate-real-part | y-coordinate-imaginary-part )
 */
void ecp2_ZZZ_serialize(uint8_t *buffer_out,
                        ECP2_ZZZ *point);

/*
 * De-serialize an ECP2_ZZZ point.
 *
 * Format: ( 0x04 | x-coordinate | y-coordinate )
 *
 * Returns:
 * 0 on success
 * -1 if the point is not on the curve
 */
int ecp2_ZZZ_deserialize(ECP2_ZZZ *point_out,
                         uint8_t *buffer);

#ifdef __cplusplus
}
#endif

#endif

