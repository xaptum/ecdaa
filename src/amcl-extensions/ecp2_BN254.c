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

#include "./ecp2_BN254.h"

size_t ecp2_BN254_length(void)
{
    return ECP2_BN254_LENGTH;
}

void ecp2_BN254_set_to_generator(ECP2_BN254 *point)
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

void ecp2_BN254_serialize(uint8_t *buffer_out,
                         ECP2_BN254 *point)
{
    buffer_out[0] = 0x04;

    octet as_oct = {.len = 0,
                    .max = ECP2_BN254_LENGTH,
                    .val = (char*)buffer_out + 1};

    ECP2_BN254_toOctet(&as_oct, point);
}

int ecp2_BN254_deserialize(ECP2_BN254 *point_out,
                           uint8_t *buffer)
{
    // 1) Check that serialized point was properly formatted.
    if (0x4 != buffer[0])
        return -2;

    // 2) Get the xa, xb, ya, yb coordinates.
	BIG_256_56 xa, xb, ya, yb;
    BIG_256_56_fromBytes(xa, (char*)&(buffer[1]));
    BIG_256_56_fromBytes(xb, (char*)&(buffer[MODBYTES_256_56+1]));
    BIG_256_56_fromBytes(ya, (char*)&(buffer[2*MODBYTES_256_56+1]));
    BIG_256_56_fromBytes(yb, (char*)&(buffer[3*MODBYTES_256_56+1]));

    // 3) Check the coordinates are valid Fp points
    //  (i.e. that they are less-than modulus)
    //  (step 2 in X9.62 Sec 5.2.2)
    BIG_256_56 q;
    BIG_256_56_rcopy(q, Modulus_BN254);
    if (1 == BIG_256_56_comp(xa, q))
        return -1;
    if (1 == BIG_256_56_comp(xb, q))
        return -1;
    if (1 == BIG_256_56_comp(ya, q))
        return -1;
    if (1 == BIG_256_56_comp(yb, q))
        return -1;

    // 4) Check that point is on curve (ECP2_BN254_set does this implicitly).
    //      (step 3 in X9.62 Sec 5.2.2)
    FP2_BN254 wx, wy;
    FP_BN254_nres(&(wx.a), xa);
    FP_BN254_nres(&(wx.b), xb);
    FP_BN254_nres(&(wy.a), ya);
    FP_BN254_nres(&(wy.b), yb);
    if (!ECP2_BN254_set(point_out, &wx, &wy))
        return -1;

    // 5) Check that point is not the identity.
    //      (step 1 in X9.62 Sec 5.2.2)
    if (ECP2_BN254_isinf(point_out)) {
        return -1;
    }

    // TODO: How to check for subgroup attack? How get cofactor of G2?

    return 0;
}
