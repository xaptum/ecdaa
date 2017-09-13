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

#ifndef ECDAA_PAIRING_BN254_H
#define ECDAA_PAIRING_BN254_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <amcl/ecp_BN254.h>
#include <amcl/ecp2_BN254.h>
#include <amcl/fp12_BN254.h>

#include <stddef.h>

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

