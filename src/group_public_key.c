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

#include <ecdaa/group_public_key.h>

#include "pairing_curve_utils.h"

size_t serialized_group_public_key_length(void)
{
    return SERIALIZED_GROUP_PUBLIC_KEY_LENGTH;
}

void ecdaa_serialize_group_public_key(uint8_t *buffer_out,
                                      struct ecdaa_group_public_key *gpk)
{
    serialize_point2(buffer_out, &gpk->X);
    serialize_point2(buffer_out + serialized_point_length_2(), &gpk->Y);
}

int ecdaa_deserialize_group_public_key(struct ecdaa_group_public_key *gpk_out,
                                       uint8_t *buffer_in)
{
    int ret = 0;

    int deserial_ret_x = deserialize_point2(&gpk_out->X, buffer_in);
    if (0 != deserial_ret_x)
        ret = -1;

    if (0 == deserial_ret_x) {
        int member_ret_x = check_point_membership2(&gpk_out->X);
        if (0 != member_ret_x)
            ret = -2;
    }

    int deserial_ret_y = deserialize_point2(&gpk_out->Y, buffer_in + serialized_point_length_2());
    if (0 != deserial_ret_y)
        ret = -1;

    if (0 == deserial_ret_y) {
        int member_ret_y = check_point_membership2(&gpk_out->Y);
        if (0 != member_ret_y)
            ret = -2;
    }

    return ret;
}
