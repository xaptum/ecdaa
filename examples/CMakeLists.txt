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

macro(expand_example template_file)
        execute_process(COMMAND python3 ${PROJECT_SOURCE_DIR}/cmake/template_expansion.py
                                        --template ${template_file}
                                        --word-size ${WORD_SIZE}
                                        --curves ${ECDAA_CURVES}
                                        --out-dir ${TOPLEVEL_BINARY_DIR}
                                        --top-level-dir ${PROJECT_SOURCE_DIR}
                                        --names-only
                OUTPUT_VARIABLE processed_file_names)

        add_custom_command(OUTPUT ${processed_file_names}
                COMMAND python3 ${PROJECT_SOURCE_DIR}/cmake/template_expansion.py
                                --template ${template_file}
                                --word-size ${WORD_SIZE}
                                --curves ${ECDAA_CURVES}
                                --out-dir ${TOPLEVEL_BINARY_DIR}
                                --top-level-dir ${PROJECT_SOURCE_DIR}
                DEPENDS ${template_file})

        list(APPEND ECDAA_EXAMPLE_SRCS ${processed_file_names})
endmacro()

file(GLOB_RECURSE ECDAA_EXAMPLE_FILES "*.c")

foreach(template_file ${ECDAA_EXAMPLE_FILES})
  expand_example(${template_file})
endforeach()

foreach(main_file ${ECDAA_EXAMPLE_SRCS})
        get_filename_component(program_name ${main_file} NAME_WE)

        add_executable(${program_name} ${main_file})

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
endforeach(main_file ${ECDAA_PROGRAM_MAIN_FILES})
