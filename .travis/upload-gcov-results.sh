#!/bin/bash

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
