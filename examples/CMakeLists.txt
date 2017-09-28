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

list(APPEND CMAKE_MODULE_PATH CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/../contrib/)
find_package(ECDAA REQUIRED QUIET)

add_definitions("-Wno-unused-function")

set(CURRENT_PROGRAMS_BINARY_DIR ${CMAKE_BINARY_DIR}/bin/)

set(ECDAA_PROGRAM_MAIN_FILES
        extract_group_public_key.c
        issuer_create_group.c
        issuer_respond_to_join_request.c
        member_process_join_response.c
        member_request_join.c
        member_sign.c
        verify.c
        )

foreach(main_file ${ECDAA_PROGRAM_MAIN_FILES})
        get_filename_component(program_name ${main_file} NAME_WE)

        add_executable(${program_name} ${main_file})

        target_link_libraries(${program_name}
                PRIVATE ecdaa
                )

        set_target_properties(${program_name} PROPERTIES
                RUNTIME_OUTPUT_DIRECTORY ${CURRENT_PROGRAMS_BINARY_DIR}
                )

        add_dependencies(${program_name} ecdaa)
endforeach(main_file ${ECDAA_PROGRAM_MAIN_FILES})
