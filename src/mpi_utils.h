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

#ifndef XAPTUM_ECDAA_MPI_UTILS_H
#define XAPTUM_ECDAA_MPI_UTILS_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <amcl/big_256_56.h>
#include <amcl/amcl.h>
#include <amcl/randapi.h>

#include <stdint.h>

/*
 * Hash the supplied message and convert to a MPI.
 *
 * Output MPI is un-normalized (and _not_ modulo any group order).
 *
 * Intermediate memory is cleared.
 */
void hash_into_mpi(BIG_256_56 *mpi_out,
                   const uint8_t *msg_in,
                   uint32_t msg_len);

/*
 * Same as hash_into_mpi, but with two input messages.
 */
void hash_into_mpi_two(BIG_256_56 *mpi_out,
                       const uint8_t *msg1_in,
                       uint32_t msg1_len,
                       const uint8_t *msg2_in,
                       uint32_t msg2_len);

/*
 * Multiply two MPIs, then add the product to a third MPI, all modulo a given modulus.
 *
 * mpi_out = [ summand + (multiplicand1 * multiplicand2) ] mod modulus
 *
 * Inputs don't need to be normalized, and will be normalized (and reduced modulo `modulus`) after return.
 * Output is normalized.
 */
void mpi_mod_mul_and_add(BIG_256_56 *mpi_out,
                         BIG_256_56 summand,
                         BIG_256_56 multiplicand1,
                         BIG_256_56 multiplicand2,
                         BIG_256_56 modulus);

#ifdef __cplusplus
}
#endif

#endif
