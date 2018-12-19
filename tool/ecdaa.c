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

#include <ecdaa.h>

#include "issuer_gen_keys_ZZZ.h"
#include "extract_gpk_ZZZ.h"
#include "member_gen_keys_ZZZ.h"
#include "issuer_issue_credential_ZZZ.h"
#include "member_process_credential_ZZZ.h"
#include "member_sign_ZZZ.h"
#include "verify_ZZZ.h"
#include "parse_cli.h"

#define EXPAND_CURVE_CASE(command, curve, ...) \
    case curve: \
        out = command ## _ ## curve(__VA_ARGS__); \
        break;

int main(int argc, char **argv) {
    struct cli_params params;

    parse_cli(argc, argv, &params);
    int out = 0;
    switch(params.command){
        case action_issuer_gen_keys:
            switch (params.curve) {
                EXPAND_CURVE_CASE(issuer_gen_keys, ZZZ, params.ipk, params.isk)
                default:
                    out = UNKNOWN_CURVE_ERROR;
                    break;
            }
            break;
        case action_extract_gpk:
            switch (params.curve) {
                EXPAND_CURVE_CASE(extract_gpk, ZZZ, params.ipk, params.gpk)
                default:
                    out = UNKNOWN_CURVE_ERROR;
                    break;
            }
            break;
        case action_member_gen_keys:
            switch (params.curve) {
                EXPAND_CURVE_CASE(member_gen_keys, ZZZ, params.nonce, params.pk, params.sk)
                default:
                    out = UNKNOWN_CURVE_ERROR;
                    break;
            }
            break;
        case action_issue_credential:
            switch (params.curve) {
                EXPAND_CURVE_CASE(issuer_issue_credential, ZZZ, params.pk, params.isk, params.cred, params.cred_sig, params.nonce)
                default:
                    out = UNKNOWN_CURVE_ERROR;
                    break;
            }
            break;
        case action_process_credential:
            switch (params.curve) {
                EXPAND_CURVE_CASE(member_process_credential, ZZZ, params.pk, params.gpk, params.cred, params.cred_sig)
                default:
                    out = UNKNOWN_CURVE_ERROR;
                    break;
            }
            break;
        case action_sign:
            switch (params.curve) {
                EXPAND_CURVE_CASE(member_sign, ZZZ, params.sk, params.cred, params.sig, params.message, params.basename)
                default:
                    out = UNKNOWN_CURVE_ERROR;
                    break;
            }
            break;
        case action_verify:
            switch (params.curve) {
                EXPAND_CURVE_CASE(verify, ZZZ, params.message, params.sig, params.gpk, params.sk_rev_list, params.num_sk_revs, params.bsn_rev_list, params.num_bsn_revs, params.basename)
                default:
                    out = UNKNOWN_CURVE_ERROR;
                    break;
            }
            break;
        case action_help:
            break;
    }

    switch(out){
        case WRITE_TO_FILE_ERROR:
            fprintf(stderr, "Error writing to a file\n");
            break;
        case READ_FROM_FILE_ERROR:
            fprintf(stderr, "Error reading a file\n");
            break;
        case KEY_CREATION_ERROR:
            fprintf(stderr, "Error creating a key pair\n");
            break;
        case DESERIALIZE_KEY_ERROR:
            fprintf(stderr, "Error deserializing a key\n");
            break;
        case VERIFY_ERROR:
            fprintf(stderr, "Signature doesn't verify\n");
            break;
        case CRED_CREATION_ERROR:
            fprintf(stderr, "Error creating DAA credentials\n" );
            break;
        case PARSE_REVOC_LIST_ERROR:
            fprintf(stderr, "Error while parsing a revocation list\n" );
            break;
        case SIGNING_ERROR:
            fprintf(stderr, "Error while signing\n");
            break;
        case UNKNOWN_CURVE_ERROR:
            fprintf(stderr, "Unrecognized curve name: '%d'\n", params.curve);
            break;
        case SUCCESS:
            fprintf(stderr, "ok\n");
            break;
    }

    if (out != SUCCESS)
        return 1;

    return 0;
}
