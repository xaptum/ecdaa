#!/bin/bash

set -e

if [[ $# -ne 2 ]]; then
        echo "usage: $0 <tool directory> <tmp directory>"
        exit 1
fi

tool_dir="$1"
tmp_dir="$2"

echo "Generating issuer keys..."
${tool_dir}/ecdaa issuer genkeys -p ${tmp_dir}/ipk.bin -s ${tmp_dir}/isk.bin

echo "Generating member keys..."
${tool_dir}/ecdaa member genkeys -p ${tmp_dir}/pk.bin -s ${tmp_dir}/sk.bin

echo "Extracting issuer's group public key..."
${tool_dir}/ecdaa extractgpk -p ${tmp_dir}/ipk.bin -g ${tmp_dir}/gpk.bin

echo "Create a credential, and credential signature, on the member's public key..."
${tool_dir}/ecdaa issuer issuecredential -p ${tmp_dir}/pk.bin -s ${tmp_dir}/isk.bin \
        -c ${tmp_dir}/cred.bin -r ${tmp_dir}/cred_sig.bin

echo "Validate a credential issued for the given member public key..."
${tool_dir}/ecdaa member processcredential -p ${tmp_dir}/pk.bin -g ${tmp_dir}/gpk.bin -c \
        ${tmp_dir}/cred.bin -r ${tmp_dir}/cred_sig.bin

echo "ECDAATESTMESSAGE" > ${tmp_dir}/message.bin

echo "Create a DAA signature over the message..."
${tool_dir}/ecdaa member sign -s ${tmp_dir}/sk.bin -g ${tmp_dir}/sig.bin -c \
        ${tmp_dir}/cred.bin -m ${tmp_dir}/message.bin

echo "Verify the signature..."
${tool_dir}/ecdaa verify -s ${tmp_dir}/sig.bin -g ${tmp_dir}/gpk.bin -m ${tmp_dir}/message.bin

echo "Check that signature does NOT verify for a revoked secret key..."
set +e
${tool_dir}/ecdaa verify -s ${tmp_dir}/sig.bin -g ${tmp_dir}/gpk.bin -m ${tmp_dir}/message.bin \
        -k ${tmp_dir}/sk.bin -e 1
verify_rc=$?
if [[ 0 -eq $verify_rc ]]; then
        echo "Error: expected failed verification, but return code was $verify_rc"
        exit 1
fi
set -e

echo "badECDAATESTMESSAGE" > ${tmp_dir}/message_bad.bin

echo "Check that signature does NOT verify for a different message..."
set +e
${tool_dir}/ecdaa verify -s ${tmp_dir}/sig.bin -g ${tmp_dir}/gpk.bin -m ${tmp_dir}/message_bad.bin
verify_rc=$?
if [[ 0 -eq $verify_rc ]]; then
        echo "Error: expected failed verification, but return code was $verify_rc"
        exit 1
fi
set -e
