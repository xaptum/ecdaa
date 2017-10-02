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

if [[ $# -ne 1 ]]; then
        echo "usage: $0 <absolute-path-to-libsodium-installation-directory>"
        exit 1
fi

version=1.0.13
install_dir="$1"
mkdir -p ${install_dir}
cd ${install_dir}
wget https://download.libsodium.org/libsodium/releases/libsodium-${version}.tar.gz
tar xvfz libsodium-${version}.tar.gz
cd libsodium-${version}
./configure --prefix=$install_dir
make
make install
