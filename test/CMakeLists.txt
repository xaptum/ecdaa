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

include(CTest)

set(CURRENT_TEST_BINARY_DIR ${CMAKE_BINARY_DIR}/testBin/)

file(GLOB_RECURSE TEST_FILES "*.c")

foreach(template_file ${TEST_FILES})
        execute_process(COMMAND python3 ${PROJECT_SOURCE_DIR}/cmake/template_expansion.py
                                        --template ${template_file}
                                        --curves ${ECDAA_CURVES}
                                        --out-dir ${CMAKE_BINARY_DIR}
                                        --top-level-dir ${PROJECT_SOURCE_DIR}
                                        --names-only
                OUTPUT_VARIABLE processed_file_names)

        add_custom_command(OUTPUT ${processed_file_names}
                COMMAND python3 ${PROJECT_SOURCE_DIR}/cmake/template_expansion.py
                                --template ${template_file}
                                --curves ${ECDAA_CURVES}
                                --out-dir ${CMAKE_BINARY_DIR}
                                --top-level-dir ${PROJECT_SOURCE_DIR}
                DEPENDS ${template_file})

        list(APPEND TEST_SRCS ${processed_file_names})
endforeach(template_file ${FILES_TO_PROCESS})

file(COPY ecdaa-test-utils.h DESTINATION ${CMAKE_BINARY_DIR}/test/)

foreach(case_file ${TEST_SRCS})
  get_filename_component(case_name ${case_file} NAME_WE)

  add_executable(${case_name} ${case_file})
  target_link_libraries(${case_name}
    PRIVATE ecdaa
    )
  target_include_directories(${case_name}
          PRIVATE ${PROJECT_SOURCE_DIR}/include/ecdaa/
          PRIVATE ${CMAKE_BINARY_DIR}/
          )
  set_target_properties(${case_name} PROPERTIES
          RUNTIME_OUTPUT_DIRECTORY ${CURRENT_TEST_BINARY_DIR}
          )

  add_test(NAME ${case_name}
          COMMAND ${CURRENT_TEST_BINARY_DIR}/${case_name}
          )

  add_dependencies(${case_name} ecdaa)
endforeach()

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/integration-tests.py ${CURRENT_TEST_BINARY_DIR}/integration-tests.py)
add_test(NAME integration-tests
        COMMAND python "${CURRENT_TEST_BINARY_DIR}/integration-tests.py" "${CMAKE_BINARY_DIR}/bin/")
