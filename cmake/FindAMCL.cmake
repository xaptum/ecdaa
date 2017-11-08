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

include(ExternalProject)

set(AMCL_PREFIX ${CMAKE_CURRENT_BINARY_DIR}/amcl/)
set(AMCL_SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/../amcl/version3/c/)
set(AMCL_HEADER_DIR ${CMAKE_CURRENT_BINARY_DIR}/amcl/amcl/)

set(AMCL_CURVE_TYPES BN254 BN254CX BLS383 FP256BN)
set(AMCL_CURVE_CONFIG_NUMBERS 17 18 19 20)

set(AMCL_CONFIG_OPTIONS "")
foreach(curve ${ECDAA_CURVES})
        list(FIND AMCL_CURVE_TYPES ${curve} curve_index)
        list(GET AMCL_CURVE_CONFIG_NUMBERS ${curve_index} curve_config_num)
        list(APPEND AMCL_CONFIG_OPTIONS "${curve_config_num}")
endforeach(curve ${ECDAA_CURVES})
list(APPEND AMCL_CONFIG_OPTIONS "0\\n")
string(REPLACE ";" "\\n" AMCL_CONFIG_OPTIONS "${AMCL_CONFIG_OPTIONS}")

if (NOT TARGET AMCL)
        ExternalProject_Add(AMCL
                PREFIX ${AMCL_PREFIX} 

                SOURCE_DIR ${AMCL_SOURCE_DIR}

                PATCH_COMMAND sh -c "cp ${AMCL_SOURCE_DIR}/* ${AMCL_PREFIX}/"

                CONFIGURE_COMMAND cd ${AMCL_PREFIX} && printf "${AMCL_CONFIG_OPTIONS}" | python3 config64.py

                # The python config script also does the building
                BUILD_COMMAND ""

                INSTALL_COMMAND sh -c "mkdir -p ${AMCL_HEADER_DIR} && cp ${AMCL_PREFIX}/*.h ${AMCL_HEADER_DIR}"
        )
endif()

set(AMCL_INCLUDE_DIRS "${CMAKE_CURRENT_BINARY_DIR}/amcl/")
set(AMCL_LIBRARIES "${CMAKE_CURRENT_BINARY_DIR}/amcl/amcl.a")

set(AMCL_FOUND TRUE)
