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

if [[ $# -eq 0 ]]; then
        toplevel_dir="`pwd`"
elif [[ $# -eq 1 ]]; then
        toplevel_dir="$1"
else
        echo "usage: $0 <path-to-toplevel-directory>"
        exit 1
fi

# "error-exitcode" makes bugs cause non-zero return code
# TODO: Add enable=all once we have tests using _all_ functions
cppcheck -v --std=c99 --error-exitcode=6 ${toplevel_dir}/include/ ${toplevel_dir}/src/ ${toplevel_dir}/test/
