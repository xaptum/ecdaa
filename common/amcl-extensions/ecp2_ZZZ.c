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

#include "./ecp2_ZZZ.h"

size_t ecp2_ZZZ_length(void)
{
    return ECP2_ZZZ_LENGTH;
}

void ecp2_ZZZ_set_to_generator(ECP2_ZZZ *point)
{
    BIG_XXX xa, xb, ya, yb;
    FP2_YYY x, y;

    BIG_XXX_rcopy(xa, CURVE_Pxa_ZZZ);
    BIG_XXX_rcopy(xb, CURVE_Pxb_ZZZ);
    BIG_XXX_rcopy(ya, CURVE_Pya_ZZZ);
    BIG_XXX_rcopy(yb, CURVE_Pyb_ZZZ);

    FP2_YYY_from_BIGs(&x, xa, xb);
    FP2_YYY_from_BIGs(&y, ya, yb);

    ECP2_ZZZ_set(point, &x, &y);
}

void ecp2_ZZZ_serialize(uint8_t *buffer_out,
                        ECP2_ZZZ *point)
{
    buffer_out[0] = 0x04;

    octet as_oct = {.len = 0,
                    .max = ECP2_ZZZ_LENGTH,
                    .val = (char*)buffer_out + 1};

    ECP2_ZZZ_toOctet(&as_oct, point);
}

int ecp2_ZZZ_deserialize(ECP2_ZZZ *point_out,
                         uint8_t *buffer)
{
    // 1) Check that serialized point was properly formatted.
    if (0x4 != buffer[0])
        return -2;

    // 2) Get the xa, xb, ya, yb coordinates.
	BIG_XXX xa, xb, ya, yb;
    BIG_XXX_fromBytes(xa, (char*)&(buffer[1]));
    BIG_XXX_fromBytes(xb, (char*)&(buffer[MODBYTES_XXX+1]));
    BIG_XXX_fromBytes(ya, (char*)&(buffer[2*MODBYTES_XXX+1]));
    BIG_XXX_fromBytes(yb, (char*)&(buffer[3*MODBYTES_XXX+1]));

    // 3) Check the coordinates are valid Fp points
    //  (i.e. that they are less-than modulus)
    //  (step 2 in X9.62 Sec 5.2.2)
    BIG_XXX q;
    BIG_XXX_rcopy(q, Modulus_ZZZ);
    if (1 == BIG_XXX_comp(xa, q))
        return -1;
    if (1 == BIG_XXX_comp(xb, q))
        return -1;
    if (1 == BIG_XXX_comp(ya, q))
        return -1;
    if (1 == BIG_XXX_comp(yb, q))
        return -1;

    // 4) Check that point is on curve (ECP2_ZZZ_set does this implicitly).
    //      (step 3 in X9.62 Sec 5.2.2)
    FP2_YYY wx, wy;
    FP_YYY_nres(&(wx.a), xa);
    FP_YYY_nres(&(wx.b), xb);
    FP_YYY_nres(&(wy.a), ya);
    FP_YYY_nres(&(wy.b), yb);
    if (!ECP2_ZZZ_set(point_out, &wx, &wy))
        return -1;

    // 5) Check that point is not the identity.
    //      (step 1 in X9.62 Sec 5.2.2)
    if (ECP2_ZZZ_isinf(point_out)) {
        return -1;
    }

    // 6) Check that point is in the proper subgroup
    //  (step 4 in X9.62 Sec 5.2.2)
    //  (check order*point == inf).
    ECP2_ZZZ point_copy;
    ECP2_ZZZ_copy(&point_copy, point_out);

    BIG_XXX curve_order;
    BIG_XXX_rcopy(curve_order, CURVE_Order_ZZZ);
    ECP2_ZZZ_mul(&point_copy, curve_order);

    if (!ECP2_ZZZ_isinf(&point_copy)) {
        return -1;
    }

    return 0;
}
