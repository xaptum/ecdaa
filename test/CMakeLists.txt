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

macro(add_test_case case_file)
  get_filename_component(case_name ${case_file} NAME_WE)
  set(case_name "ecdaa-${case_name}")

  add_executable(${case_name} ${case_file} $<TARGET_OBJECTS:ecdaa_utilities>)

  if(BUILD_SHARED_LIBS)
          target_link_libraries(${case_name} PRIVATE
                                ecdaa)
  else()
          target_link_libraries(${case_name} PRIVATE
                                ecdaa_static)
  endif()

  target_include_directories(${case_name}
          PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
                  $<BUILD_INTERFACE:${ECDAA_INTERNAL_UTILITIES_INCLUDE_DIR}>
                  ${TOPLEVEL_BINARY_DIR}/libecdaa
                  ${PROJECT_SOURCE_DIR}/libecdaa
  )

  set_target_properties(${case_name} PROPERTIES
          RUNTIME_OUTPUT_DIRECTORY ${CURRENT_TEST_BINARY_DIR}
  )

  add_test(NAME ${case_name}
          COMMAND ${CURRENT_TEST_BINARY_DIR}/${case_name}
  )
endmacro()

set(CURRENT_TEST_BINARY_DIR ${TOPLEVEL_BINARY_DIR}/testBin/)

set(ECDAA_TEST_FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/big_XXX-tests.c
        ${CMAKE_CURRENT_SOURCE_DIR}/credential_ZZZ-tests.c
        ${CMAKE_CURRENT_SOURCE_DIR}/ecp2_ZZZ-tests.c
        ${CMAKE_CURRENT_SOURCE_DIR}/ecp_ZZZ-tests.c
        ${CMAKE_CURRENT_SOURCE_DIR}/group_public_key_ZZZ-tests.c
        ${CMAKE_CURRENT_SOURCE_DIR}/issuer_keypair_ZZZ-tests.c
        ${CMAKE_CURRENT_SOURCE_DIR}/member_keypair_ZZZ-tests.c
        ${CMAKE_CURRENT_SOURCE_DIR}/schnorr_ZZZ-tests.c
        ${CMAKE_CURRENT_SOURCE_DIR}/signature_ZZZ-tests.c

        ${CMAKE_CURRENT_SOURCE_DIR}/schnorr_ZZZ-fuzz.c
        )

foreach(template_file ${ECDAA_TEST_FILES})
        expand_template(${template_file} ECDAA_TEST_SRCS FALSE FALSE)
endforeach()

foreach(case_file ${ECDAA_TEST_SRCS})
        add_test_case(${case_file})
endforeach()

# Add the integration-tests python script
if(BUILD_EXAMPLES)
        configure_file(${CMAKE_CURRENT_SOURCE_DIR}/integration-tests.py ${CURRENT_TEST_BINARY_DIR}/ecdaa-integration-tests.py)
        add_test(NAME ecdaa-integration-tests
                COMMAND python "${CURRENT_TEST_BINARY_DIR}/ecdaa-integration-tests.py" "${TOPLEVEL_BINARY_DIR}/bin/")
endif()

################################################################################
# TPM
################################################################################
if(ECDAA_TPM_SUPPORT)
        add_subdirectory(tpm)
endif()

set(CURRENT_TEST_BINARY_DIR ${CMAKE_BINARY_DIR}/testBin/)

#add tests for tool
add_test(NAME "tool_test"
  COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tool-test.sh
  ${PROJECT_SOURCE_DIR}/build/tool
  ${CURRENT_TEST_BINARY_DIR}
  )
