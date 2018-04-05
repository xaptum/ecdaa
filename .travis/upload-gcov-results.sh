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

if [[ $# -ne 1 ]]; then
        echo "usage: $0 <path-to-cmake-build-directory>"
        exit 1
fi

build_dir="$1"
gcov_dir="${build_dir}/gcov-results"

cd "$build_dir"

mkdir -p "$gcov_dir"

for f in $(find . -name "*.gcda" -o -name "*.gcno"); do
        cp -f "$f" ${gcov_dir}/
done
for f in $(find ../../src -name "*.c"); do
        cp -f "$f" ${gcov_dir}/
done

cd $gcov_dir
gcov *.c
source <(curl -s https://codecov.io/bash)
