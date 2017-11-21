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

project(ecdaa
        LANGUAGES C
        VERSION "0.1.1")

option(DISABLE_LIBSODIUM_RNG_SEED_FUNCTION
        "Disable the default Libsodium-based seed function"
        OFF)

option(ECDAA_BUILD_EXAMPLE_PROGRAMS
        "Build the top-level driver programs for running ECDAA task"
        ON)

set(CURVE_TYPES BN254 BN254CX BLS383 FP256BN)
if(NOT ECDAA_CURVES)
        set(ECDAA_CURVES ${CURVE_TYPES})
endif(NOT ECDAA_CURVES)
foreach(curve ${ECDAA_CURVES})
        list(FIND CURVE_TYPES ${curve} curve_index)
        if(${curve_index} EQUAL -1)
                MESSAGE(ERROR ": Curve type ${curve} not supported")
        endif(${curve_index} EQUAL -1)
endforeach(curve ${ECDAA_CURVES})

list(APPEND CMAKE_MODULE_PATH CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
find_package(AMCL REQUIRED QUIET)

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

if(NOT DISABLE_LIBSODIUM_RNG_SEED_FUNCTION)
        SET(ECDAA_SEED_LINK_LIBRARY sodium)
else(NOT DISABLE_LIBSODIUM_RNG_SEED_FUNCTION)
        SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DDISABLE_LIBSODIUM_RNG_SEED_FUNCTION")
endif(NOT DISABLE_LIBSODIUM_RNG_SEED_FUNCTION)

set(GENERATED_TOPLEVEL_INCLUDE_DIR "${CMAKE_BINARY_DIR}/include")

file(GLOB PUBLIC_HEADERS "include/ecdaa/*.h")
file(GLOB_RECURSE IMPLEMENTATION_H_FILES "src/*.h")
file(GLOB_RECURSE IMPLEMENTATION_C_FILES "src/*.c")
set(FILES_TO_PROCESS ${PUBLIC_HEADERS} ${IMPLEMENTATION_H_FILES} ${IMPLEMENTATION_C_FILES})

foreach(template_file ${FILES_TO_PROCESS})
        execute_process(COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/cmake/template_expansion.py
                                        --template ${template_file}
                                        --curves ${ECDAA_CURVES}
                                        --out-dir ${CMAKE_BINARY_DIR}
                                        --top-level-dir ${CMAKE_CURRENT_SOURCE_DIR}
                                        --names-only
                OUTPUT_VARIABLE processed_file_names)

        add_custom_command(OUTPUT ${processed_file_names}
                COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/cmake/template_expansion.py
                                --template ${template_file}
                                --curves ${ECDAA_CURVES}
                                --out-dir ${CMAKE_BINARY_DIR}
                                --top-level-dir ${CMAKE_CURRENT_SOURCE_DIR}
                DEPENDS ${template_file})

        list(APPEND SRCS ${processed_file_names})
endforeach(template_file ${FILES_TO_PROCESS})

set(TOPLEVEL_HEADER ${GENERATED_TOPLEVEL_INCLUDE_DIR}/ecdaa.h)
add_custom_target(toplevel_header
        COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/cmake/template_expansion.py
                        --template ${CMAKE_CURRENT_SOURCE_DIR}/include/ecdaa.h 
                        --curves ${ECDAA_CURVES}
                        --out-dir ${CMAKE_BINARY_DIR}
                        --top-level-dir ${CMAKE_CURRENT_SOURCE_DIR}
                        --top-level-header)

add_custom_target(generate_sources DEPENDS ${SRCS} toplevel_header)

add_library(ecdaa
        ${SRCS}
        )

target_include_directories(ecdaa
        PUBLIC
        ${AMCL_INCLUDE_DIRS}
        ${GENERATED_TOPLEVEL_INCLUDE_DIR}
        )

add_dependencies(ecdaa AMCL)
add_dependencies(ecdaa toplevel_header)

target_link_libraries(ecdaa
        PRIVATE ${AMCL_LIBRARIES}
        ${ECDAA_SEED_LINK_LIBRARY})

if(ECDAA_BUILD_EXAMPLE_PROGRAMS)
        set(ECDAA_PROGRAMS_DIR examples)
        add_subdirectory(${ECDAA_PROGRAMS_DIR})
endif(ECDAA_BUILD_EXAMPLE_PROGRAMS)

enable_testing()
add_subdirectory(test)
