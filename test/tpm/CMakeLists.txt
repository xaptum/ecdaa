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

option(TEST_USE_TCP_TPM "Use the socket-based TCTI in the tests" OFF)

if(TEST_USE_TCP_TPM)
        add_definitions(-DUSE_TCP_TPM)
endif()

expand_template(${CMAKE_CURRENT_SOURCE_DIR}/tpm_ZZZ-test-utils.h ECDAA_TPM_UTILS_LIST TRUE)

macro(add_tpm_test_case case_file)
  get_filename_component(case_name ${case_file} NAME_WE)
  set(case_name "ecdaa-${case_name}")

  add_executable(${case_name} ${case_file} $<TARGET_OBJECTS:ecdaa_utilities> ${ECDAA_TPM_UTILS_LIST})

  if(BUILD_SHARED_LIBS)
          target_link_libraries(${case_name} PRIVATE
                                ecdaa-tpm)
  else()
          target_link_libraries(${case_name} PRIVATE
                                ecdaa-tpm_static)
  endif()

  target_include_directories(${case_name}
          PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
                  $<BUILD_INTERFACE:${ECDAA_INTERNAL_UTILITIES_INCLUDE_DIR}>
                  ${TOPLEVEL_BINARY_DIR}/libecdaa
                  ${TOPLEVEL_BINARY_DIR}/libecdaa-tpm
  )

  set_target_properties(${case_name} PROPERTIES
          RUNTIME_OUTPUT_DIRECTORY ${CURRENT_TEST_BINARY_DIR}
  )

  if(NOT case_file MATCHES ".*create_tpm_key-util.*")
    add_test(NAME ${case_name}
            COMMAND ${CURRENT_TEST_BINARY_DIR}/${case_name}
    )
  endif()
endmacro()

set(ECDAA_TPM_TEST_FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/schnorr_TPM_ZZZ-tests.c
        ${CMAKE_CURRENT_SOURCE_DIR}/signature_TPM_ZZZ-tests.c
        ${CMAKE_CURRENT_SOURCE_DIR}/tpm_ZZZ-test.c
        ${CMAKE_CURRENT_SOURCE_DIR}/create_tpm_key-util.c
        )

foreach(template_file ${ECDAA_TPM_TEST_FILES})
        expand_template(${template_file} ECDAA_TPM_TEST_SRCS TRUE)
endforeach()

foreach(case_file ${ECDAA_TPM_TEST_SRCS})
        add_tpm_test_case(${case_file})
endforeach()
