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

#include "pairing_curve_utils.h"

#include <amcl/randapi.h>
#include <amcl/fp2_BN254.h>
#include <amcl/pair_BN254.h>

void random_num_mod_order(BIG_256_56 *num_out, csprng *rng)
{
    BIG_256_56 curve_order;
    BIG_256_56_rcopy(curve_order, CURVE_Order_BN254);

    BIG_256_56_randomnum(*num_out, curve_order, rng);
}

void set_to_basepoint(ECP_BN254 *point)
{
    BIG_256_56 gx, gy;
    BIG_256_56_rcopy(gx, CURVE_Gx_BN254);
    BIG_256_56_rcopy(gy, CURVE_Gy_BN254);
    ECP_BN254_set(point, gx, gy);
}

void set_to_basepoint2(ECP2_BN254 *point)
{
    BIG_256_56 xa, xb, ya, yb;
    FP2_BN254 x, y;

    BIG_256_56_rcopy(xa, CURVE_Pxa_BN254);
    BIG_256_56_rcopy(xb, CURVE_Pxb_BN254);
    BIG_256_56_rcopy(ya, CURVE_Pya_BN254);
    BIG_256_56_rcopy(yb, CURVE_Pyb_BN254);

    FP2_BN254_from_BIGs(&x, xa, xb);
    FP2_BN254_from_BIGs(&y, ya, yb);

    ECP2_BN254_set(point, &x, &y);
}

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
