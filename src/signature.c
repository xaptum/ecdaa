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

#include <ecdaa/signature.h>

#include "pairing_curve_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

size_t serialized_signature_length()
{
    return SERIALIZED_SIGNATURE_LENGTH;
}

void ecdaa_serialize_signature(uint8_t *buffer_out,
                               ecdaa_signature_t *signature)
{
    BIG_256_56_toBytes((char*)buffer_out, signature->c);
    BIG_256_56_toBytes((char*)(buffer_out + MODBYTES_256_56), signature->s);

    serialize_point(buffer_out + 2*MODBYTES_256_56, &signature->R);
    serialize_point(buffer_out + 2*MODBYTES_256_56 + serialized_point_length(), &signature->S);
    serialize_point(buffer_out + 2*MODBYTES_256_56 + 2*serialized_point_length(), &signature->T);
    serialize_point(buffer_out + 2*MODBYTES_256_56 + 3*serialized_point_length(), &signature->W);
}

int ecdaa_deserialize_signature(ecdaa_signature_t *signature_out,
                                uint8_t *buffer_in)
{
    int ret = 0;

    BIG_256_56_fromBytes(signature_out->c, (char*)buffer_in);
    BIG_256_56_fromBytes(signature_out->s, (char*)(buffer_in + MODBYTES_256_56));

    if (0 != deserialize_point(&signature_out->R, buffer_in + MODBYTES_256_56))
        ret = -1;

    if (0 != deserialize_point(&signature_out->S, buffer_in + MODBYTES_256_56 + serialized_point_length()))
        ret = -1;

    if (0 != deserialize_point(&signature_out->T, buffer_in + MODBYTES_256_56 + 2*serialized_point_length()))
        ret = -1;

    if (0 != deserialize_point(&signature_out->W, buffer_in + MODBYTES_256_56 + 3*serialized_point_length()))
        ret = -1;

    return ret;
}
