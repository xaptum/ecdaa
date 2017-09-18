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

cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

list(APPEND CMAKE_MODULE_PATH CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)
find_package(AMCL REQUIRED QUIET)

project(ecdaa
        LANGUAGES C
        VERSION "0.1.1")

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror -Wall -Wextra -std=c99")

SET(CMAKE_C_FLAGS_DEBUGWITHCOVERAGE "${CMAKE_C_FLAGS_DEBUGWITHCOVERAGE} -O0 -fprofile-arcs -ftest-coverage")

SET(CMAKE_C_FLAGS_RELWITHSANITIZE "${CMAKE_C_FLAGS_RELWITHSANITIZE} -O2 -g -fsanitize=address,undefined -fsanitize=unsigned-integer-overflow")

# The following options are automatically passed to the `memcheck` executable:
# `--error-exitcode=5` A memory error causes a return code of 5, so memory errors will fail the tests.
# `--leak-check=full` Search for memory leaks after program completion, and give a full report for each individually.
#   - As we're striving for "malloc-free" code, we expect to have zero memory leaks
# `-v` Verbose `memcheck` output
# `--track-origins=yes` Track the origin of uninitialized values (small Valgrind performance hit)
# `--partial-loads-ok=no` Loads from partially invalid addresses are treated the same as loads from completely invalid addresses
find_program(MEMORYCHECK_COMMAND NAMES valgrind)
set(MEMORYCHECK_COMMAND_OPTIONS
        "--error-exitcode=5 --leak-check=full -v --track-origins=yes --partial-loads-ok=no")

set(ECDAA_SRC_DIR src)
set(ECDAA_INTERNAL_SRC_DIR ${ECDAA_SRC_DIR}/internal/)
set(ECDAA_AMCL_EXTENSIONS_SRC_DIR ${ECDAA_SRC_DIR}/amcl-extensions/)
set(ECDAA_TEST_DIR test)
set(ECDAA_SRCS
        ${ECDAA_SRC_DIR}/credential_BN254.c
        ${ECDAA_SRC_DIR}/group_public_key_BN254.c
        ${ECDAA_SRC_DIR}/issuer_keypair_BN254.c
        ${ECDAA_SRC_DIR}/member_keypair_BN254.c
        ${ECDAA_SRC_DIR}/signature_BN254.c
        ${ECDAA_INTERNAL_SRC_DIR}/explicit_bzero.c
        ${ECDAA_INTERNAL_SRC_DIR}/schnorr.c
        ${ECDAA_AMCL_EXTENSIONS_SRC_DIR}/big_256_56.c
        ${ECDAA_AMCL_EXTENSIONS_SRC_DIR}/ecp_BN254.c
        ${ECDAA_AMCL_EXTENSIONS_SRC_DIR}/ecp2_BN254.c
        ${ECDAA_AMCL_EXTENSIONS_SRC_DIR}/pairing_BN254.c
        ${ECDAA_TEST_DIR}/ecdaa-test-utils.c
        )

add_library(ecdaa ${ECDAA_SRCS})

add_dependencies(ecdaa AMCL)

target_include_directories(ecdaa
        PUBLIC include
        PUBLIC ${AMCL_INCLUDE_DIRS})

target_link_libraries(ecdaa
        PUBLIC ${AMCL_LIBRARIES})

enable_testing()
add_subdirectory(${ECDAA_TEST_DIR})
