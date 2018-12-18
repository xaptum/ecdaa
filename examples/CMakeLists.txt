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

add_compile_options("-Wno-unused-function")

set(CURRENT_PROGRAMS_BINARY_DIR ${TOPLEVEL_BINARY_DIR}/bin/)

add_library(ecdaa_examples_rand OBJECT ${CMAKE_CURRENT_SOURCE_DIR}/examples_rand.c)

macro(add_example example_file)
        get_filename_component(program_name ${example_file} NAME_WE)

        add_executable(${program_name} ${example_file} $<TARGET_OBJECTS:ecdaa_examples_rand>)

        target_include_directories(${program_name}
          PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
        )

        if(BUILD_SHARED_LIBS)
              target_link_libraries(${program_name} PRIVATE ecdaa)
        else()
              target_link_libraries(${program_name} PRIVATE ecdaa_static)
        endif()

        set_target_properties(${program_name} PROPERTIES
                RUNTIME_OUTPUT_DIRECTORY ${CURRENT_PROGRAMS_BINARY_DIR}
        )

        install(TARGETS ${program_name} RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endmacro()

set(ECDAA_EXAMPLE_FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/ecdaa_extract_group_public_key.c
        ${CMAKE_CURRENT_SOURCE_DIR}/ecdaa_issuer_create_group.c
        ${CMAKE_CURRENT_SOURCE_DIR}/ecdaa_issuer_respond_to_join_request.c
        ${CMAKE_CURRENT_SOURCE_DIR}/ecdaa_member_process_join_response.c
        ${CMAKE_CURRENT_SOURCE_DIR}/ecdaa_member_request_join.c
        ${CMAKE_CURRENT_SOURCE_DIR}/ecdaa_member_sign.c
        ${CMAKE_CURRENT_SOURCE_DIR}/ecdaa_verify.c
        )

foreach(template_file ${ECDAA_EXAMPLE_FILES})
  expand_template(${template_file} ECDAA_EXAMPLE_SRCS FALSE FALSE)
endforeach()

foreach(example_file ${ECDAA_EXAMPLE_SRCS})
  add_example(${example_file})
endforeach()
