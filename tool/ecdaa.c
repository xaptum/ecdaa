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
#include "ecdaa_issuer_create_group.h"
#include "ecdaa_extract_group_public_key.h"
#include "ecdaa_member_request_join.h"
#include "ecdaa_issuer_respond_to_join_request.h"
#include "ecdaa_member_process_join_response.h"
#include "ecdaa_member_sign.h"
#include "ecdaa_verify.h"
#include <ecdaa/util/util_errors.h>
#include "parse_cli.h"

int main(int argc, char **argv) {
    struct cli_params params;

    parse_cli(argc, argv, &params);
    int out = 0;
    switch(params.command){
        case action_create_group:
            out = ecdaa_create_group(params.ipk, params.isk);
            break;
        case action_extract_gpk:
            out = ecdaa_extract_gpk(params.ipk, params.gpk);
            break;
        case action_request_join:
            out = ecdaa_member_request_join(params.nonce, params.pk, params.sk);
            break;
        case action_respond_to_request:
            out = ecdaa_issuer_respond_to_join_request(params.pk, params.isk, params.cred, params.cred_sig, params.nonce);
            break;
        case action_process_response:
            out = ecdaa_member_process_join_response(params.pk, params.gpk, params.cred, params.cred_sig);
            break;
        case action_sign:
            out = ecdaa_member_sign(params.sk, params.cred, params.sig, params.message, params.basename);
            break;
        case action_verify:
            out = ecdaa_verify(params.message, params.sig, params.gpk, params.sk_rev_list, params.num_sk_revs,
                                params.bsn_rev_list, params.num_bsn_revs, params.basename);
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
        case NONCE_OVERFLOW:
            fprintf(stderr, "Nonce input was too large\n");
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
        case SUCCESS:
            fprintf(stderr, "ok\n");
            break;
    }
}
