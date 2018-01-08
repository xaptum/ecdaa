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
        echo "usage: $0 <absolute-path-to-amcl-installation-directory> <comma-separated-curve-list>"
        exit 1
fi

repo_url=https://github.com/zanebeckwith/milagro-crypto-c
tag=headers-under-directory
install_dir="$1"
curves="$2"
git clone -b $tag "${repo_url}"
cd milagro-crypto-c
mkdir -p build
cd build
cmake .. -DAMCL_CURVE=${curves} -DBUILD_MPIN=Off -DBUILD_WCC=Off -DBUILD_DOXYGEN=Off -DUSE_PATENTS=Off -DCMAKE_INSTALL_PREFIX=${install_dir} -DBUILD_SHARED_LIBS=Off -DCMAKE_POSITION_INDEPENDENT_CODE=On
make
make install
