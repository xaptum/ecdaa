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

macro(expand_test_case template_file)
        execute_process(COMMAND python3 ${PROJECT_SOURCE_DIR}/cmake/template_expansion.py
                                        --template ${template_file}
                                        --curves ${ECDAA_CURVES}
                                        --out-dir ${TOPLEVEL_BINARY_DIR}
                                        --top-level-dir ${PROJECT_SOURCE_DIR}
                                        --names-only
                OUTPUT_VARIABLE processed_file_names)

        add_custom_command(OUTPUT ${processed_file_names}
                COMMAND python3 ${PROJECT_SOURCE_DIR}/cmake/template_expansion.py
                                --template ${template_file}
                                --curves ${ECDAA_CURVES}
                                --out-dir ${TOPLEVEL_BINARY_DIR}
                                --top-level-dir ${PROJECT_SOURCE_DIR}
                DEPENDS ${template_file})

        list(APPEND ECDAA_TEST_SRCS ${processed_file_names})
endmacro()

macro(add_test_case case_file)
  get_filename_component(case_name ${case_file} NAME_WE)

  add_executable(${case_name} ${case_file})

  if(BUILD_SHARED_LIBS)
          target_link_libraries(${case_name} PRIVATE ecdaa ${AMCL_LIBRARIES} ${ECDAA_SEED_LINK_LIBRARY})
          add_dependencies(${case_name} ecdaa)
  else()
          target_link_libraries(${case_name} PRIVATE ecdaa_static ${AMCL_LIBRARIES} ${ECDAA_SEED_LINK_LIBRARY})
          add_dependencies(${case_name} ecdaa_static)
  endif()

  target_include_directories(${case_name}
          PRIVATE ${AMCL_INCLUDE_DIRS}
          PRIVATE ${XAPTUM_TPM_INCLUDE_DIRS}
          PRIVATE ${GENERATED_TOPLEVEL_INCLUDE_DIR}
          PRIVATE ${PROJECT_SOURCE_DIR}/include/ecdaa/
          PRIVATE ${TOPLEVEL_BINARY_DIR}/
          )

  set_target_properties(${case_name} PROPERTIES
          RUNTIME_OUTPUT_DIRECTORY ${CURRENT_TEST_BINARY_DIR}
          )

  add_test(NAME ${case_name}
          COMMAND ${CURRENT_TEST_BINARY_DIR}/${case_name}
          )
endmacro()

set(CURRENT_TEST_BINARY_DIR ${TOPLEVEL_BINARY_DIR}/testBin/)

file(GLOB_RECURSE ECDAA_TEST_FILES "*.c")

if(NOT ECDAA_TPM_SUPPORT)
        foreach(file ${ECDAA_TEST_FILES})
                string(REGEX MATCH ".*tpm.*|.*TPM.*" match ${file})
                if(match)
                        list(REMOVE_ITEM ECDAA_TEST_FILES ${match})
                endif()
        endforeach()
else()
        file(COPY tpm-test-utils.h DESTINATION ${TOPLEVEL_BINARY_DIR}/test/)
endif()

foreach(template_file ${ECDAA_TEST_FILES})
        expand_test_case(${template_file})
endforeach()

file(COPY ecdaa-test-utils.h DESTINATION ${TOPLEVEL_BINARY_DIR}/test/)

foreach(case_file ${ECDAA_TEST_SRCS})
        add_test_case(${case_file})
endforeach()

# Add the integration-tests python script
if(BUILD_EXAMPLES)
        configure_file(${CMAKE_CURRENT_SOURCE_DIR}/integration-tests.py ${CURRENT_TEST_BINARY_DIR}/integration-tests.py)
        add_test(NAME integration-tests
                COMMAND python "${CURRENT_TEST_BINARY_DIR}/integration-tests.py" "${TOPLEVEL_BINARY_DIR}/bin/")
endif()
