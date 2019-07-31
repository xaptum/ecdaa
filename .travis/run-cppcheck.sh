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

if [[ $# -eq 0 ]]; then
        generated_sources_dir="`pwd`"
elif [[ $# -eq 1 ]]; then
        generated_sources_dir="$(my_expand_path $1)"
else
        echo "usage: $0 <path-to-toplevel-directory>"
        exit 1
fi

# "error-exitcode" makes bugs cause non-zero return code
cppcheck -v --std=c99 --error-exitcode=6 --enable=all --suppress=missingIncludeSystem -I ${generated_sources_dir}/include/ -I ${generated_sources_dir} -I ${generated_sources_dir}/src/ -I ${generated_sources_dir}/src/tpm-utils/ -I ${generated_sources_dir}/src/internal/ -I ${generated_sources_dir}/src/amcl-extensions/ ${generated_sources_dir}/src/ ${generated_sources_dir}/test/ ${generated_sources_dir}/examples/ --suppress=purgedConfiguration
