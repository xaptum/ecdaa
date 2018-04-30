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

#include <ecdaa/group_public_key_ZZZ.h>

#include "amcl-extensions/ecp2_ZZZ.h"

size_t ecdaa_group_public_key_ZZZ_length(void)
{
    return ECDAA_GROUP_PUBLIC_KEY_ZZZ_LENGTH;
}

void ecdaa_group_public_key_ZZZ_serialize(uint8_t *buffer_out,
                                          struct ecdaa_group_public_key_ZZZ *gpk)
{
    ecp2_ZZZ_serialize(buffer_out, &gpk->X);
    ecp2_ZZZ_serialize(buffer_out + ECP2_ZZZ_LENGTH, &gpk->Y);
}

int ecdaa_group_public_key_ZZZ_deserialize(struct ecdaa_group_public_key_ZZZ *gpk_out,
                                           uint8_t *buffer_in)
{
    int ret = 0;

    if (0 != ecp2_ZZZ_deserialize(&gpk_out->X, buffer_in))
        ret = -1;

    if (0 != ecp2_ZZZ_deserialize(&gpk_out->Y, buffer_in + ECP2_ZZZ_LENGTH))
        ret = -1;

    return ret;
}
