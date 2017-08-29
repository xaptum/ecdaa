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

#include <xaptum-ecdaa/signature.h>

#ifdef __cplusplus
extern "C" {
#endif

void ecdaa_serialize_signature(uint8_t *buffer_out,
                               uint32_t *out_length,
                               ecdaa_signature_t *signature)
{
    // TODO
    if (NULL == buffer_out || NULL == out_length || NULL == signature)
        return;
}

void ecdaa_deserialize_signature(ecdaa_signature_t *signature_out,
                                 uint8_t *buffer_in,
                                 uint32_t *in_length)
{
    // TODO
    if (NULL == buffer_in || NULL == in_length || NULL == signature_out)
        return;
}