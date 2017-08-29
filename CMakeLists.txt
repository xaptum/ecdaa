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

project(xaptum-ecdaa
        LANGUAGES C
        VERSION "0.1.0")

add_compile_options(-Werror -Wall -Wextra -std=c99)

set(XAPTUM_ECDAA_SRC_DIR src)
set(XAPTUM_ECDAA_TEST_DIR test)
set(XAPTUM_ECDAA_SRCS
        ${XAPTUM_ECDAA_SRC_DIR}/credential.c
        ${XAPTUM_ECDAA_SRC_DIR}/explicit_bzero.c
        ${XAPTUM_ECDAA_SRC_DIR}/group_public_key.c
        ${XAPTUM_ECDAA_SRC_DIR}/issuer.c
        ${XAPTUM_ECDAA_SRC_DIR}/issuer_keypair.c
        ${XAPTUM_ECDAA_SRC_DIR}/member.c
        ${XAPTUM_ECDAA_SRC_DIR}/member_keypair.c
        ${XAPTUM_ECDAA_SRC_DIR}/mpi_utils.c
        ${XAPTUM_ECDAA_SRC_DIR}/pairing_curve_utils.c
        ${XAPTUM_ECDAA_SRC_DIR}/schnorr.c
        ${XAPTUM_ECDAA_SRC_DIR}/signature.c
        ${XAPTUM_ECDAA_SRC_DIR}/verify.c
        ${XAPTUM_ECDAA_TEST_DIR}/xaptum-test-utils.c
        )

add_library(xecdaa ${XAPTUM_ECDAA_SRCS})

add_dependencies(xecdaa AMCL)

target_include_directories(xecdaa
        PUBLIC include
        PUBLIC ${AMCL_INCLUDE_DIRS})

target_link_libraries(xecdaa
        PUBLIC ${AMCL_LIBRARIES})

enable_testing()
add_subdirectory(${XAPTUM_ECDAA_TEST_DIR})
