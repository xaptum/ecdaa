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

#ifndef XAPTUM_ECDAA_PAIRING_CURVE_UTILS_H
#define XAPTUM_ECDAA_PAIRING_CURVE_UTILS_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <amcl/ecp_BN254.h>
#include <amcl/big_256_56.h>
#include <amcl/ecp2_BN254.h>
#include <amcl/fp12_BN254.h>

#include <stddef.h>

extern const size_t serialized_point_length;
extern const size_t serialized_point_length_2;

/*
 * Serialize a G1 point.
 *
 * Format: ( 0x04 | x-coordinate | y-coordinate )
 */
void serialize_point(uint8_t *buffer,
                     ECP_BN254 *point);

/*
 * Serialize a G2 point.
 *
 * Format: ( 0x04 | x-coordinate-real-part | x-coordinate-imaginary-part | y-coordinate-real-part | y-coordinate-imaginary-part )
 */
void serialize_point2(uint8_t *buffer,
                      ECP2_BN254 *point);

/*
 * Generate a uniformly-distributed pseudo-random number,
 * between [0, n], where n is the order of the EC group.
 *
 * Output is normalized.
 */
void random_num_mod_order(BIG_256_56 *num_out,
                          csprng *rng);

/*
 * Initialize G1 point to G1 generator.
 */
void set_to_basepoint(ECP_BN254 *point);

/*
 * Initialize G2 point to G2 generator.
 */
void set_to_basepoint2(ECP2_BN254 *point);

/*
 * Check if the given EC point is a member of G1.
 *
 * Returns:
 * 0 on success
 * -1 if the point is _not_ in G1
 */
int check_point_membership(ECP_BN254 *point);

/*
 * Check if the given EC point is a member of G2.
 *
 * Returns:
 * 0 on success
 * -1 if the point is _not_ in G2
 */
int check_point_membership2(ECP2_BN254 *point);

/*
 * Compute the optimal Ate pairing.
 */
void compute_pairing(FP12_BN254 *pairing_out,
                     ECP_BN254 *g1_point,
                     ECP2_BN254 *g2_point);

#ifdef __cplusplus
}
#endif

#endif

