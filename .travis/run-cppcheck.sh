#!/bin/bash
# Copyright 2017 Xaptum, Inc.
# 
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
# 
#        http://www.apache.org/licenses/LICENSE-2.0
# 
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License

set -e

source "${BASH_SOURCE%/*}/path_expansion.sh"

if [[ $# -ne 2 ]]; then
        echo "usage: $0 <toplevel-directory> <build-directory>"
        exit 1
fi

toplevel_dir="$(my_expand_path $1)"
generated_sources_dir="$(my_expand_path $2)"

# "error-exitcode" makes bugs cause non-zero return code
cppcheck -v --std=c99 --error-exitcode=6 --enable=all --suppress=missingIncludeSystem \
        -I ${toplevel_dir}/libecdaa/include/ -I ${toplevel_dir}/libecdaa-tpm/include/ \
        -I ${toplevel_dir}/common -I ${toplevel_dir}/libecdaa -I ${toplevel_dir}/libecdaa-tpm \
        -I ${toplevel_dir}/tool \
        -I ${toplevel_dir}/test -I ${toplevel_dir}/test/tpm \
        -I ${generated_sources_dir}/libecdaa/include/ -I ${generated_sources_dir}/libecdaa-tpm/include/ \
        -I ${generated_sources_dir}/common -I ${generated_sources_dir}/libecdaa -I ${generated_sources_dir}/libecdaa-tpm \
        -I ${generated_sources_dir}/tool \
        -I ${generated_sources_dir}/test -I ${generated_sources_dir}/test/tpm \
        ${generated_sources_dir}/common ${generated_sources_dir}/libecdaa/ ${generated_sources_dir}/libecdaa-tpm/ \
        ${generated_sources_dir}/tool \
        ${generated_sources_dir}/test ${generated_sources_dir}/test/tpm
