/******************************************************************************
 *
 * Copyright 2018 Xaptum, Inc.
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
 #ifndef ECDAA_TOOL_RESPOND_TO_REQUEST_ZZZ_H
 #define ECDAA_TOOL_RESPOND_TO_REQUEST_ZZZ_H
 #pragma once

 #ifdef __cplusplus
 extern "C" {
 #endif

 /*
  * Creates a issuer key pair and then serializes the public and secret keys
  *
  * Returns:
  * SUCCESS                     on success
  * CRED_CREATION_ERROR         an error occurred creating the credentials
  * DESERIALIZE_KEY_ERROR       an error occurred while deserializing a key
  * READ_FROM_FILE_ERROR        an error occurred reading keys from file
  * WRITE_TO_FILE_ERROR         an error occurred writing keys to files
  * NONCE_OVERFLOW              nonce given was too long
 */
 int issuer_respond_to_join_request_ZZZ(const char* member_public_key_file,
                                         const char* issuer_secret_key_file,
                                         const char* credential_out_file,
                                         const char* credential_signature_out_file,
                                         const char* nonce);
 #ifdef __cplusplus
 }
 #endif

 #endif
