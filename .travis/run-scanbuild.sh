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

if [[ $# -ne 2 ]]; then
        echo "usage: $0 <absolute-path-to-cmakelists-directory> <absolute-path-to-cmake-build-directory>"
        exit 1
fi

cmake_dir="$1"

build_dir="$2"
mkdir -p "$build_dir"
cd "$build_dir"
scan-build cmake "$cmake_dir" -DCMAKE_BUILD_TYPE=Debug
scan-build --status-bugs cmake --build . -- -j2 #status-bugs means a bug causes a non-zero return code
