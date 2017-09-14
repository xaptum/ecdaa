#!/bin/bash

if [[ $# -ne 1 ]]; then
        echo "usage: $0 <path-to-cmake-build-directory>"
        exit 1
fi

for f in $(find "$1" -name "MemoryChecker*.log"); do
        echo ""
        echo "############# ${f} #########################"
        echo ""
        cat $f
done
