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

list(APPEND CMAKE_MODULE_PATH CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

project(ecdaa
        LANGUAGES C
        VERSION "0.8.2")

include(GNUInstallDirs)
include(CTest)

option(DISABLE_LIBSODIUM_RNG_SEED_FUNCTION
        "Disable the default Libsodium-based seed function"
        OFF)

option(BUILD_SHARED_LIBS "Build as a shared library" ON)
option(BUILD_STATIC_LIBS "Build as a static library" OFF)

# If not building as a shared library, force build as a static.  This
# is to match the CMake default semantics of using
# BUILD_SHARED_LIBS = OFF to indicate a static build.
if (NOT DEFINED BUILD_SHARED_LIBS OR NOT  "${BUILD_SHARED_LIBS}")
  set(BUILD_STATIC_LIBS ON CACHE BOOL "Build as a static library" FORCE)
endif ()

option(ECDAA_TPM_SUPPORT "Include ECDAA functions that require a TPM" ON)

if(NOT ECDAA_CURVES)
        set(ECDAA_CURVES FP256BN)
endif()

set(ECDAA_VERSION ${PROJECT_VERSION})
set(ECDAA_SOVERSION ${PROJECT_VERSION_MAJOR})

find_package(AMCL 4.6.0 REQUIRED QUIET)
if(ECDAA_TPM_SUPPORT)
  find_package(xaptum-tpm 0.5.0 REQUIRED QUIET)
endif()

if(NOT DISABLE_LIBSODIUM_RNG_SEED_FUNCTION)
  find_package(sodium 1.0.11 REQUIRED QUIET)
  SET(ECDAA_SEED_LIBRARY sodium)
else()
  SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DDISABLE_LIBSODIUM_RNG_SEED_FUNCTION")
endif()

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror -Wall -Wextra -std=c99 -Wno-missing-field-initializers")
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

set(TOPLEVEL_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}")

set(GENERATED_TOPLEVEL_INCLUDE_DIR "${TOPLEVEL_BINARY_DIR}/include")

file(GLOB PUBLIC_HEADERS "include/ecdaa/*.h")
file(GLOB_RECURSE IMPLEMENTATION_H_FILES "src/*.h")
file(GLOB_RECURSE IMPLEMENTATION_C_FILES "src/*.c")
set(FILES_TO_PROCESS ${PUBLIC_HEADERS} ${IMPLEMENTATION_H_FILES} ${IMPLEMENTATION_C_FILES})

if(NOT ECDAA_TPM_SUPPORT)
        foreach(file ${FILES_TO_PROCESS})
                string(REGEX MATCH ".*tpm.*|.*TPM.*" match ${file})
                if(match)
                        list(REMOVE_ITEM FILES_TO_PROCESS ${match})
                endif()
        endforeach()
endif()

foreach(template_file ${FILES_TO_PROCESS})
        execute_process(COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/cmake/template_expansion.py
                                        --template ${template_file}
                                        --curves ${ECDAA_CURVES}
                                        --out-dir ${TOPLEVEL_BINARY_DIR}
                                        --top-level-dir ${CMAKE_CURRENT_SOURCE_DIR}
                                        --names-only
                OUTPUT_VARIABLE processed_file_names)

        add_custom_command(OUTPUT ${processed_file_names}
                COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/cmake/template_expansion.py
                                --template ${template_file}
                                --curves ${ECDAA_CURVES}
                                --out-dir ${TOPLEVEL_BINARY_DIR}
                                --top-level-dir ${CMAKE_CURRENT_SOURCE_DIR}
                DEPENDS ${template_file})

        list(APPEND ECDAA_SRCS ${processed_file_names})
endforeach(template_file ${FILES_TO_PROCESS})

set(TOPLEVEL_HEADER ${GENERATED_TOPLEVEL_INCLUDE_DIR}/ecdaa.h)
if (ECDAA_TPM_SUPPORT)
        set(USE_TPM_PYTHON_OPTION "--use-tpm")
endif ()
add_custom_target(toplevel_header
        COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/cmake/template_expansion.py
                        --template ${CMAKE_CURRENT_SOURCE_DIR}/include/ecdaa.h 
                        --curves ${ECDAA_CURVES}
                        --out-dir ${TOPLEVEL_BINARY_DIR}
                        --top-level-dir ${CMAKE_CURRENT_SOURCE_DIR}
                        --top-level-header
                        ${USE_TPM_PYTHON_OPTION})

add_custom_target(generate_sources DEPENDS ${ECDAA_SRCS} toplevel_header)

################################################################################
# Shared Libary
################################################################################
if (BUILD_SHARED_LIBS)
        add_library(ecdaa SHARED ${ECDAA_SRCS})

        set_target_properties(ecdaa PROPERTIES
                VERSION "${ECDAA_VERSION}"
                SOVERSION "${ECDAA_SOVERSION}"
        )

        target_include_directories(ecdaa PUBLIC
                $<BUILD_INTERFACE:${GENERATED_TOPLEVEL_INCLUDE_DIR}>
                $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        )

        target_link_libraries(ecdaa
          PUBLIC  AMCL::AMCL
          PRIVATE ${ECDAA_SEED_LIBRARY}
        )

        if (ECDAA_TPM_SUPPORT)
          target_link_libraries(ecdaa PUBLIC xaptum-tpm::xaptum-tpm)
        endif()

        install(TARGETS ecdaa
                EXPORT ecdaa-targets
                RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
                LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
                ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        )

        add_dependencies(ecdaa toplevel_header)
endif ()

################################################################################
# Static Libary
################################################################################
if (BUILD_STATIC_LIBS)
        add_library(ecdaa_static STATIC ${ECDAA_SRCS})

        set_target_properties(ecdaa_static PROPERTIES
                OUTPUT_NAME "ecdaa${STATIC_SUFFIX}"
                VERSION "${ECDAA_VERSION}"
                SOVERSION "${ECDAA_SOVERSION}"
        )

        target_include_directories(ecdaa_static PUBLIC
                $<BUILD_INTERFACE:${GENERATED_TOPLEVEL_INCLUDE_DIR}>
                $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        )

        target_link_libraries(ecdaa_static
          PUBLIC  AMCL::AMCL
          PRIVATE ${ECDAA_SEED_LIBRARY}
        )

        if (ECDAA_TPM_SUPPORT)
          target_link_libraries(ecdaa PUBLIC xaptum-tpm::xaptum-tpm)
        endif()

        install(TARGETS ecdaa_static
                EXPORT ecdaa-targets
                RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
                LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
                ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        )

        add_dependencies(ecdaa_static toplevel_header)
endif ()

################################################################################
# Headers
################################################################################
install(DIRECTORY ${GENERATED_TOPLEVEL_INCLUDE_DIR}/ecdaa
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

install(FILES ${GENERATED_TOPLEVEL_INCLUDE_DIR}/ecdaa.h
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

################################################################################
# pkgconfig
################################################################################
configure_file(ecdaa.pc.in ecdaa.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/ecdaa.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)

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

configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/ecdaa-config.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/ecdaa-config.cmake
  INSTALL_DESTINATION ${INSTALL_CONFIGDIR}
)

install(FILES
  cmake/Findsodium.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/ecdaa-config.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/ecdaa-config-version.cmake
  DESTINATION ${INSTALL_CONFIGDIR}
)

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
