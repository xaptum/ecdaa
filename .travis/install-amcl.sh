#!/bin/bash
# Copyright 2017-2018 Xaptum, Inc.
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

if [[ $# -ne 2 ]]; then
        echo "usage: $0 <absolute-path-to-amcl-source-directory> <comma-separated-curve-list>"
        exit 1
fi

repo_url=https://github.com/xaptum/amcl
tag=4.7.3
source_dir="$1"
curves="$2"
git clone -b $tag "${repo_url}" "${source_dir}"
pushd "${source_dir}"
mkdir -p build
pushd build
cmake .. -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} -DAMCL_CURVE=${curves} -DAMCL_RSA="" -DAMCL_INCLUDE_SUBDIR=amcl -DBUILD_PYTHON=Off -DBUILD_MPIN=Off -DBUILD_WCC=Off -DBUILD_DOCS=Off  -DBUILD_SHARED_LIBS=On
cmake --build .
cmake --build . --target install
popd
popd
