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

cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

list(APPEND CMAKE_MODULE_PATH CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)

project(ecdaa
        LANGUAGES C
        VERSION "0.10.3")

include(GNUInstallDirs)
include(CTest)
include(DetermineWordSize)

option(BUILD_SHARED_LIBS "Build as a shared library" ON)
option(BUILD_STATIC_LIBS "Build as a static library" OFF)

option(BUILD_BENCHMARKS "Build benchmarks" ON)
option(BUILD_EXAMPLES "Build examples" OFF)
option(BUILD_TOOL "Build with ECDAA tools" ON)

# If not building as a shared library, force build as a static.  This
# is to match the CMake default semantics of using
# BUILD_SHARED_LIBS = OFF to indicate a static build.
if(NOT BUILD_SHARED_LIBS)
  set(BUILD_STATIC_LIBS ON CACHE BOOL "Build as a static library" FORCE)
endif()

option(ECDAA_TPM_SUPPORT "Include ECDAA functions that require a TPM" ON)

determine_word_size(DEFAULT_WORD_SIZE)
set(WORD_SIZE ${DEFAULT_WORD_SIZE} CACHE STRING "Word length in bits. See ./include/arch.h")
set_property(CACHE WORD_SIZE PROPERTY STRINGS "16;32;64")

if(WORD_SIZE STREQUAL "")
  message(FATAL_ERROR "Must explicitly set WORD_SIZE.")
endif()

if(NOT ECDAA_CURVES)
        set(ECDAA_CURVES FP256BN)
endif()

set(ECDAA_VERSION ${PROJECT_VERSION})
set(ECDAA_SOVERSION ${PROJECT_VERSION_MAJOR})

find_package(AMCL 4.7.0 REQUIRED QUIET)
if(ECDAA_TPM_SUPPORT)
  find_package(xaptum-tpm 0.5.0 REQUIRED QUIET)
endif()

add_compile_options(-std=c99 -Wall -Wextra -Wno-missing-field-initializers)
SET(CMAKE_C_FLAGS_DEBUGWITHCOVERAGE "${CMAKE_C_FLAGS_DEBUGWITHCOVERAGE} -O0 -fprofile-arcs -ftest-coverage")
SET(CMAKE_C_FLAGS_RELWITHSANITIZE "${CMAKE_C_FLAGS_RELWITHSANITIZE} -O2 -g -fsanitize=address,undefined")
SET(CMAKE_C_FLAGS_DEV "${CMAKE_C_FLAGS_RELEASE} -Werror")
SET(CMAKE_C_FLAGS_DEVDEBUG "${CMAKE_C_FLAGS_DEBUG} -Werror")

set(TOPLEVEL_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}")

macro(expand_template template_file srcs_list use_tpm is_tool)
        if (${use_tpm})
                set(use_tpm_flag "--use-tpm")
        endif()

        if (${is_tool})
                set(is_tool_flag "--tool")
        endif()

        execute_process(COMMAND python3 ${PROJECT_SOURCE_DIR}/cmake/template_expansion.py
                                        --template ${template_file}
                                        --word-size ${WORD_SIZE}
                                        --curves ${ECDAA_CURVES}
                                        --out-dir ${TOPLEVEL_BINARY_DIR}
                                        --top-level-dir ${PROJECT_SOURCE_DIR}
                                        --names-only
                                        ${use_tpm_flag}
                RESULT_VARIABLE processed_file_result
                ERROR_VARIABLE processed_file_stderr
                OUTPUT_VARIABLE processed_file_names)

        if(NOT "${processed_file_result}" STREQUAL "0")
                message(FATAL_ERROR "Error processing template ${template_file}: ${processed_file_stderr}")
        endif()

        add_custom_command(OUTPUT ${processed_file_names}
                COMMAND python3 ${PROJECT_SOURCE_DIR}/cmake/template_expansion.py
                                --template ${template_file}
                                --word-size ${WORD_SIZE}
                                --curves ${ECDAA_CURVES}
                                --out-dir ${TOPLEVEL_BINARY_DIR}
                                --top-level-dir ${PROJECT_SOURCE_DIR}
                                ${use_tpm_flag}
                                ${is_tool_flag}
                DEPENDS ${template_file})

        list(APPEND ${srcs_list} ${processed_file_names})
endmacro()

add_subdirectory(common)

################################################################################
# libecdaa
################################################################################
add_subdirectory(libecdaa)

################################################################################
# libecdaa-tpm
################################################################################
if(ECDAA_TPM_SUPPORT)
  add_subdirectory(libecdaa-tpm)
endif()

################################################################################
# Examples
################################################################################
if(BUILD_EXAMPLES)
        add_subdirectory(examples)
endif()

################################################################################
# Tests
################################################################################
if (BUILD_TESTING)
        add_subdirectory(test)
endif()

################################################################################
# Tool
################################################################################
if (BUILD_TOOL)
        add_subdirectory(tool)
endif()

################################################################################
# Benchmarks
################################################################################
if (BUILD_BENCHMARKS)
        add_subdirectory(benchmarks)
endif()

################################################################################
# CMake export
################################################################################
set(INSTALL_CONFIGDIR ${CMAKE_INSTALL_LIBDIR}/cmake/ecdaa)

install(EXPORT ecdaa-targets
        FILE ecdaa-targets.cmake
        NAMESPACE ecdaa::
        DESTINATION ${INSTALL_CONFIGDIR}
)

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/ecdaa-config-version.cmake
  VERSION ${ECDAA_VERSION}
  COMPATIBILITY SameMajorVersion
)

configure_package_config_file(${PROJECT_SOURCE_DIR}/ecdaa-config.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/ecdaa-config.cmake
  INSTALL_DESTINATION ${INSTALL_CONFIGDIR}
)

install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/ecdaa-config.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/ecdaa-config-version.cmake
  DESTINATION ${INSTALL_CONFIGDIR}
)
