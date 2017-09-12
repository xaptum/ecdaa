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

#include "./pairing_BN254.h"

#include <amcl/fp2_BN254.h>
#include <amcl/pair_BN254.h>

void compute_pairing(FP12_BN254 *pairing_out,
                     ECP_BN254 *g1_point,
                     ECP2_BN254 *g2_point)
{
    // TODO: Why is this necessary?
    // (it looks like only _add and _sub don't convert to affine)
    // (but, why is affine necessary for ate computation?)
    ECP_BN254_affine(g1_point);
    ECP2_BN254_affine(g2_point);

    PAIR_BN254_ate(pairing_out, g2_point, g1_point);
    PAIR_BN254_fexp(pairing_out);
}
