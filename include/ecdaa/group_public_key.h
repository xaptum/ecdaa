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

#ifndef XAPTUM_ECDAA_GROUP_PUBLIC_KEY_H
#define XAPTUM_ECDAA_GROUP_PUBLIC_KEY_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <amcl/ecp2_BN254.h>

#include <stdint.h>

/*
 * Public key for the DAA group.
 */
struct ecdaa_group_public_key {
    ECP2_BN254 X;
    ECP2_BN254 Y;
};

#define SERIALIZED_GROUP_PUBLIC_KEY_LENGTH (2*(4*MODBYTES_256_56 + 1))
size_t serialized_group_public_key_length(void);

/*
 * Serialize an `ecdaa_group_public_key`
 *
 * The serialized format is:
 *  ( 0x04 | X.x-coord-real | X.x-coord-imaginary | X.y-coord-real | X.y-coord-imaginary |
 *      0x04 | Y.x-coord-real | Y.x-coord-imaginary | Y.y-coord-real | Y.y-coord-imaginary )
 *  where all numbers are zero-padded and in big-endian byte-order.
 *
 * The provided buffer is assumed to be large enough.
 */
void ecdaa_serialize_group_public_key(uint8_t *buffer_out,
                                      struct ecdaa_group_public_key *gpk);

/*
 * De-serialize an `ecdaa_group_public_key` and check it for validity.
 *
 * The serialized format is expected to be:
 *  ( 0x04 | X.x-coord-real | X.x-coord-imaginary | X.y-coord-real | X.y-coord-imaginary |
 *      0x04 | Y.x-coord-real | Y.x-coord-imaginary | Y.y-coord-real | Y.y-coord-imaginary )
 *  where all numbers are zero-padded and in big-endian byte-order.
 *
 *  Returns:
 *  0 on success
 *  -1 if either X or Y aren't a point on the curve
 *  -2 if either X or Y aren't in G2
 */
int ecdaa_deserialize_group_public_key(struct ecdaa_group_public_key *gpk_out,
                                       uint8_t *buffer_in);

#ifdef __cplusplus
}
#endif

#endif

