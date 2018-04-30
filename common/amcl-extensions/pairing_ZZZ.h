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

#ifndef ECDAA_PAIRING_ZZZ_H
#define ECDAA_PAIRING_ZZZ_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <amcl/ecp_ZZZ.h>
#include <amcl/ecp2_ZZZ.h>
#include <amcl/fp12_ZZZ.h>

#include <stddef.h>

/*
 * Compute the optimal Ate pairing.
 */
void compute_pairing_ZZZ(FP12_YYY *pairing_out,
                         ECP_ZZZ *g1_point,
                         ECP2_ZZZ *g2_point);

#ifdef __cplusplus
}
#endif

#endif

