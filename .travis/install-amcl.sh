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

source "${BASH_SOURCE%/*}/path_expansion.sh"

if [[ $# -ne 3 ]]; then
        echo "usage: $0 <source-download-target> <install-target> <comma-separated-curve-list>"
        exit 1
fi

repo_url=https://github.com/xaptum/amcl
tag=4.7.3
source_dir="$(my_expand_path $1)"
install_dir="$(my_expand_path $2)"
curves="$3"

rm -rf "${source_dir}"
git clone -b $tag "${repo_url}" "${source_dir}"
pushd "${source_dir}"
mkdir -p build
pushd build
cmake .. -DCMAKE_INSTALL_PREFIX=${install_dir} -DAMCL_CURVE=${curves} -DAMCL_RSA="" -DAMCL_INCLUDE_SUBDIR=amcl -DBUILD_PYTHON=Off -DBUILD_MPIN=Off -DBUILD_WCC=Off -DBUILD_DOCS=Off  -DBUILD_SHARED_LIBS=On
cmake --build .
cmake --build . --target install
popd
popd
