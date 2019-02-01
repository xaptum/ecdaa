#!/bin/bash
#
# Attempt to build a project that depends on ecdaa,
# to test that an installation of ecdaa works correctly.

set -e

if [[ $# -ne 3 ]]; then
        echo "usage: $0 <ecdaa installation directory> <system install directory> <tmp directory>"
        exit 1
fi

install_dir="$1"
sys_install_dir="$2"
tmp_dir="$3"
output_file=${tmp_dir}/installation-test.out

function cleanup()
{
        rm -f $output_file
}
trap cleanup INT KILL EXIT

LIB_DIR="${install_dir}/lib"
SYS_LIB_DIR="${sys_install_dir}/lib"

INCLUDE_FLAGS="-I${install_dir}/include -I${sys_install_dir}/include"
LINKER_FLAGS="-L${LIB_DIR} -L${SYS_LIB_DIR}/lib -lecdaa -lecdaa-tpm"

echo "Attempting to build downstream program..."
cc $INCLUDE_FLAGS -x c - -o $output_file -std=c99 $LINKER_FLAGS <<'EOF'
#include <stdio.h>
#include <ecdaa.h>
#include <ecdaa-tpm.h>
int main() {
printf("It worked!\n");
}
EOF
echo "ok"

echo "Attempting to run downstream executable..."
export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${LIB_DIR}:${SYS_LIB_DIR}
${output_file}
echo "ok"
