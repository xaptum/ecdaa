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

if [[ $# -eq 1 ]]; then
        valgrind_cmd=valgrind
elif [[ $# -eq 2 ]]; then
        valgrind_cmd="${2}"
else
        echo "usage: $0 <path-to-cmake-build-directory> [<absolute-path-to-valgrind-executable>]"
        exit 1
fi

build_dir="$1"
mkdir -p "$build_dir"
cd "$build_dir"
${valgrind_cmd} --tool=exp-sgcheck ctest -VV -E benchmarks
