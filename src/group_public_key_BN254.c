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

#include <ecdaa/group_public_key_BN254.h>

#include "./amcl-extensions/ecp2_BN254.h"

size_t ecdaa_group_public_key_BN254_length(void)
{
    return ECDAA_GROUP_PUBLIC_KEY_BN254_LENGTH;
}

void ecdaa_group_public_key_BN254_serialize(uint8_t *buffer_out,
                                            struct ecdaa_group_public_key_BN254 *gpk)
{
    ecp2_BN254_serialize(buffer_out, &gpk->X);
    ecp2_BN254_serialize(buffer_out + ECP2_BN254_LENGTH, &gpk->Y);
}

int ecdaa_group_public_key_BN254_deserialize(struct ecdaa_group_public_key_BN254 *gpk_out,
                                             uint8_t *buffer_in)
{
    int ret = 0;

    int deserial_ret_x = ecp2_BN254_deserialize(&gpk_out->X, buffer_in);
    if (0 != deserial_ret_x)
        ret = -1;

    if (0 == deserial_ret_x) {
        int member_ret_x = ecp2_BN254_check_membership(&gpk_out->X);
        if (0 != member_ret_x)
            ret = -2;
    }

    int deserial_ret_y = ecp2_BN254_deserialize(&gpk_out->Y, buffer_in + ECP2_BN254_LENGTH);
    if (0 != deserial_ret_y)
        ret = -1;

    if (0 == deserial_ret_y) {
        int member_ret_y = ecp2_BN254_check_membership(&gpk_out->Y);
        if (0 != member_ret_y)
            ret = -2;
    }

    return ret;
}
