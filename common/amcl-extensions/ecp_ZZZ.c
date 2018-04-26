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

#include "./ecp_ZZZ.h"
#include "./big_XXX.h"

size_t ecp_ZZZ_length(void)
{
    return ECP_ZZZ_LENGTH;
}

void ecp_ZZZ_set_to_generator(ECP_ZZZ *point)
{
    BIG_XXX gx, gy;
    BIG_XXX_rcopy(gx, CURVE_Gx_ZZZ);
    BIG_XXX_rcopy(gy, CURVE_Gy_ZZZ);
    ECP_ZZZ_set(point, gx, gy);
}

void ecp_ZZZ_serialize(uint8_t *buffer_out,
                       ECP_ZZZ *point)
{
    octet as_oct = {.len = 0,
                    .max = ECP_ZZZ_LENGTH,
                    .val = (char*)buffer_out};

    ECP_ZZZ_toOctet(&as_oct, point);
}

int ecp_ZZZ_deserialize(ECP_ZZZ *point_out,
                        uint8_t *buffer)
{
    // 1) Check that serialized point was properly formatted.
    if (0x4 != buffer[0])
        return -2;

    // 2) Get the x,y coordinates.
    BIG_XXX wx, wy;
    BIG_XXX_fromBytes(wx, (char*)&(buffer[1]));
    BIG_XXX_fromBytes(wy, (char*)&(buffer[MODBYTES_XXX+1]));

    // 3) Check the coordinates are valid Fp points
    //  (i.e. that they are less-than modulus)
    //  (step 2 in X9.62 Sec 5.2.2)
    BIG_XXX q;
    BIG_XXX_rcopy(q, Modulus_ZZZ);
    if (1 == BIG_XXX_comp(wx, q))
        return -1;
    if (1 == BIG_XXX_comp(wy, q))
        return -1;

    // 4) Check that point is on curve (ECP_ZZZ_set does this implicitly).
    //      (step 3 in X9.62 Sec 5.2.2)
    if (!ECP_ZZZ_set(point_out, wx, wy)) {
        return -1;
    }

    // 5) Check that point is not the identity.
    //      (step 1 in X9.62 Sec 5.2.2)
    if (ECP_ZZZ_isinf(point_out)) {
        return -1;
    }

    // 6) Check that point is in the proper subgroup
    //  (step 4 in X9.62 Sec 5.2.2)
    //  (order*point == inf is equivalent to cofactor*point != inf).
    ECP_ZZZ point_copy;
    ECP_ZZZ_copy(&point_copy, point_out);

    BIG_XXX cof;
    BIG_XXX_rcopy(cof, CURVE_Cof_ZZZ);
    ECP_ZZZ_mul(&point_copy, cof);

    if (ECP_ZZZ_isinf(&point_copy)) {
        return -1;
    }

    return 0;
}

int32_t ecp_ZZZ_fromhash(ECP_ZZZ *point_out, const uint8_t *message, uint32_t message_length)
{
    // Following the Appendix of Chen and Li, 2013

    BIG_XXX curve_order;
    BIG_XXX_rcopy(curve_order, CURVE_Order_ZZZ);

    for (int32_t i=0; i < 232; i++) {
        BIG_XXX x;
        big_XXX_from_two_message_hash(&x, (uint8_t*)&i, sizeof(i), message, message_length);
        BIG_XXX_mod(x, curve_order);
        // Check if generated point is on curve:
        //  (the 0 indicates we want the y-coord with lsb=0)
        if (ECP_ZZZ_setx(point_out, x, 0)) {
            // If on curve, and cofactor != 1, multiply by cofactor to get on correct subgroup.
            BIG_XXX cofactor;
            BIG_XXX_rcopy(cofactor, CURVE_Cof_ZZZ);
            if (!BIG_XXX_isunity(cofactor)) {
                ECP_ZZZ_mul(point_out, cofactor);
            }
            return i;
        }
    }

    // If we reach here, we ran out of tries, so return error.
    return -1;
}

void ecp_ZZZ_random_mod_order(BIG_XXX *big_out,
                              csprng *rng)
{
    BIG_XXX curve_order;
    BIG_XXX_rcopy(curve_order, CURVE_Order_ZZZ);

    BIG_XXX_randomnum(*big_out, curve_order, rng);
}

