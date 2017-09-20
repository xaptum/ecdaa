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

#include "./ecp_BN254.h"

size_t ecp_BN254_length(void)
{
    return ECP_BN254_LENGTH;
}

void ecp_BN254_set_to_generator(ECP_BN254 *point)
{
    BIG_256_56 gx, gy;
    BIG_256_56_rcopy(gx, CURVE_Gx_BN254);
    BIG_256_56_rcopy(gy, CURVE_Gy_BN254);
    ECP_BN254_set(point, gx, gy);
}

void ecp_BN254_serialize(uint8_t *buffer_out,
                         ECP_BN254 *point)
{
    octet as_oct = {.len = 0,
                    .max = ECP_BN254_LENGTH,
                    .val = (char*)buffer_out};

    ECP_BN254_toOctet(&as_oct, point);
}

int ecp_BN254_deserialize(ECP_BN254 *point_out,
                          uint8_t *buffer)
{
    // 1) Check that serialized point was properly formatted.
    if (0x4 != buffer[0])
        return -2;

    // 2) Get the x,y coordinates.
    BIG_256_56 wx, wy;
    BIG_256_56_fromBytes(wx, (char*)&(buffer[1]));
    BIG_256_56_fromBytes(wy, (char*)&(buffer[MODBYTES_256_56+1]));

    // 3) Check the coordinates are valid Fp points
    //  (i.e. that they are less-than modulus)
    //  (step 2 in X9.62 Sec 5.2.2)
    BIG_256_56 q;
    BIG_256_56_rcopy(q, Modulus_BN254);
    if (1 == BIG_256_56_comp(wx, q))
        return -1;
    if (1 == BIG_256_56_comp(wy, q))
        return -1;

    // 4) Check that point is on curve (ECP_BN254_set does this implicitly).
    //      (step 3 in X9.62 Sec 5.2.2)
    if (!ECP_BN254_set(point_out, wx, wy)) {
        return -1;
    }

    // 5) Check that point is not the identity.
    //      (step 1 in X9.62 Sec 5.2.2)
    if (ECP_BN254_isinf(point_out)) {
        return -1;
    }

    // 6) Check that point is in the proper subgroup
    //  (step 4 in X9.62 Sec 5.2.2)
    //  (order*point == inf is equivalent to cofactor*point != inf).
    ECP_BN254 point_copy;
    ECP_BN254_copy(&point_copy, point_out);

    BIG_256_56 cof;
    BIG_256_56_rcopy(cof, CURVE_Cof_BN254);
    ECP_BN254_mul(&point_copy, cof);

    if (ECP_BN254_isinf(&point_copy)) {
        return -1;
    }

    return 0;
}
