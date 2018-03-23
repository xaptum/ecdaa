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

add_definitions("-Wno-unused-function")

set(CURRENT_PROGRAMS_BINARY_DIR ${TOPLEVEL_BINARY_DIR}/bin/)

set(ECDAA_PROGRAM_MAIN_FILES
        ecdaa_extract_group_public_key.c
        ecdaa_issuer_create_group.c
        ecdaa_issuer_respond_to_join_request.c
        ecdaa_member_process_join_response.c
        ecdaa_member_request_join.c
        ecdaa_member_sign.c
        ecdaa_verify.c
        )

foreach(main_file ${ECDAA_PROGRAM_MAIN_FILES})
        get_filename_component(program_name ${main_file} NAME_WE)

        add_executable(${program_name} ${main_file})

        target_include_directories(${program_name} PRIVATE
                ${GENERATED_TOPLEVEL_INCLUDE_DIR})

        if(BUILD_SHARED_LIBS)
              target_link_libraries(${program_name} PRIVATE AMCL::AMCL ecdaa)
              add_dependencies(${program_name} ecdaa)
        else()
              target_link_libraries(${program_name} PRIVATE ecdaa_static AMCL::AMCL)
              add_dependencies(${program_name} ecdaa_static)
        endif()

        set_target_properties(${program_name} PROPERTIES
                RUNTIME_OUTPUT_DIRECTORY ${CURRENT_PROGRAMS_BINARY_DIR}
                )

        if(NOT BUILD_SHARED_LIBS)
                install(TARGETS ${program_name} DESTINATION ${CMAKE_INSTALL_BINDIR})
        endif()
endforeach(main_file ${ECDAA_PROGRAM_MAIN_FILES})
