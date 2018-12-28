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

#ifndef PARSE_CLI_H
#define PARSE_CLI_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    action_issuer_gen_keys,
    action_extract_gpk,
    action_member_gen_keys,
    action_issue_credential,
    action_process_credential,
    action_sign,
    action_verify,
    action_help
} action;

typedef enum {
    ZZZ,
} curve_name;

extern const char *curve_name_strings[];

struct cli_params{
    action command;
    curve_name curve;
    const char* ipk;
    const char* isk;
    const char* gpk;
    const char* nonce;
    const char* pk;
    const char* sk;
    const char* cred;
    const char* cred_sig;
    const char* sig;
    const char* message;
    const char* basename;
    const char *sk_rev_list;
    const char* num_sk_revs;
    const char *bsn_rev_list;
    const char* num_bsn_revs;
    const char *basename_file;

};

void parse_cli(int argc, char **argv, struct cli_params *params);

#ifdef __cplusplus
}
#endif

#endif
