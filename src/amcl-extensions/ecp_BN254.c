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

size_t ecp_BN254_length()
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

int ecp_BN254_check_membership(ECP_BN254 *point)
{
    // TODO: Check if this is correct!
    ECP_BN254 point_copy;
    ECP_BN254_copy(&point_copy, point);

    BIG_256_56 curve_order;
    BIG_256_56_rcopy(curve_order, CURVE_Order_BN254);

    /* Check point is not in wrong group */
    int nb = BIG_256_56_nbits(curve_order);
    BIG_256_56 k;
    BIG_256_56_one(k);
    BIG_256_56_shl(k, (nb+4)/2);
    BIG_256_56_add(k, curve_order, k);
    BIG_256_56_sdiv(k, curve_order); /* get co-factor */

    while (BIG_256_56_parity(k) == 0) {
        ECP_BN254_dbl(&point_copy);
        BIG_256_56_fshr(k,1);
    }

    if (!BIG_256_56_isunity(k))
        ECP_BN254_mul(&point_copy,k);
    if (ECP_BN254_isinf(&point_copy))
        return -1;

    return 0;
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
                          const uint8_t *buffer)
{
    int ret = 0;

    octet as_oct = {.len = 0,
                    .max = ECP_BN254_LENGTH,
                    .val = (char*)buffer};

    int from_ret = ECP_BN254_fromOctet(point_out, &as_oct);
    if (1 != from_ret)
        ret = -1;

    return ret;
}
