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
        echo "usage: $0 <installation-path-for-valgrind>"
        exit 1
fi

cd "$1"

git clone git://sourceware.org/git/valgrind.git
cd valgrind
git checkout 621cde90f7d23e916d3ce2716df02d261a72f5f3   # The commit with our needed fix
./autogen.sh
./configure --prefix=`pwd`
make -j4
make install
