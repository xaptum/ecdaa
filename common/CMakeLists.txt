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

set(ECDAA_INTERNAL_UTILITIES_INPUT_FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/amcl-extensions/big_XXX.h
        ${CMAKE_CURRENT_SOURCE_DIR}/amcl-extensions/ecp2_ZZZ.h
        ${CMAKE_CURRENT_SOURCE_DIR}/amcl-extensions/ecp_ZZZ.h
        ${CMAKE_CURRENT_SOURCE_DIR}/amcl-extensions/pairing_ZZZ.h
        ${CMAKE_CURRENT_SOURCE_DIR}/amcl-extensions/big_XXX.c
        ${CMAKE_CURRENT_SOURCE_DIR}/amcl-extensions/ecp2_ZZZ.c
        ${CMAKE_CURRENT_SOURCE_DIR}/amcl-extensions/ecp_ZZZ.c
        ${CMAKE_CURRENT_SOURCE_DIR}/amcl-extensions/pairing_ZZZ.c
        ${CMAKE_CURRENT_SOURCE_DIR}/internal-utilities/explicit_bzero.h
        ${CMAKE_CURRENT_SOURCE_DIR}/internal-utilities/explicit_bzero.c
        ${CMAKE_CURRENT_SOURCE_DIR}/internal-utilities/rand_pool.h
        ${CMAKE_CURRENT_SOURCE_DIR}/internal-utilities/rand_pool.c
        )

foreach(template_file ${ECDAA_INTERNAL_UTILITIES_INPUT_FILES})
        expand_template(${template_file} ECDAA_INTERNAL_UTILITIES_SRCS FALSE FALSE)
endforeach()

set(ECDAA_INTERNAL_UTILITIES_INCLUDE_DIR "${TOPLEVEL_BINARY_DIR}/common")
set(ECDAA_INTERNAL_UTILITIES_INCLUDE_DIR "${TOPLEVEL_BINARY_DIR}/common" PARENT_SCOPE)

add_library(ecdaa_utilities OBJECT ${ECDAA_INTERNAL_UTILITIES_SRCS})

if (BUILD_SHARED_LIBS)
        set_target_properties(ecdaa_utilities PROPERTIES POSITION_INDEPENDENT_CODE ON)
endif()

message ("")
message ("######################################")
message ("$<TARGET_PROPERTY:AMCL::core,INTERFACE_INCLUDE_DIRECTORIES>")
message ("")
message ("")

get_cmake_property(_variableNames VARIABLES)
list (SORT _variableNames)
foreach (_variableName ${_variableNames})
    message(STATUS "${_variableName}=${${_variableName}}")
endforeach()

target_include_directories(ecdaa_utilities
        PUBLIC ${ECDAA_INTERNAL_UTILITIES_INCLUDE_DIR}
        PUBLIC $<TARGET_PROPERTY:AMCL::core,INTERFACE_INCLUDE_DIRECTORIES>
        )
