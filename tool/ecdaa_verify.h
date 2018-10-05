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
 #ifndef ECDAA_UTIL_VERIFY_H
 #define ECDAA_UTIL_VERIFY_H
 #pragma once

 #ifdef __cplusplus
 extern "C" {
 #endif

 /*
  * Creates a issuer key pair and then serializes the public and secret keys
  *
  * Returns:
  * SUCCESS                     on success
  * SIGNING_ERROR               an error occurred while signing message
  * PARSE_REVOC_LIST_ERROR      an error occurred while parsing a revocation list
  * DESERIALIZE_KEY_ERROR       an error occurred while deserializing key
  * READ_FROM_FILE_ERROR        an error occurred while reading from a file
  * WRITE_TO_FILE_ERROR         an error occurred while writing to a file
 */
 int ecdaa_verify(const char *message_file, const char *sig_file, const char *gpk_file, const char *sk_rev_list_file,
                 const char *number_of_sk_revs, const char *bsn_rev_list_file, const char *number_of_bsn_revs, const char *basename_file);

 #ifdef __cplusplus
 }
 #endif

 #endif
