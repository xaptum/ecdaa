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

set(TEST_SRCS
        sign-and-verify-tests.c
        issuer_keypair-tests.c
        credential-tests.c
        member_keypair-tests.c
        big_256_56-tests.c
        ecp_BN254-tests.c
        ecp2_BN254-tests.c
        schnorr-tests.c
        )

foreach(case_file ${TEST_SRCS})
  get_filename_component(case_name ${case_file} NAME_WE)

  add_executable(${case_name} ${case_file})
  target_link_libraries(${case_name}
    PRIVATE xecdaa
    )
  target_include_directories(${case_name}
          PRIVATE ${PROJECT_SOURCE_DIR}/include/ecdaa/
          )
  set_target_properties(${case_name} PROPERTIES
          RUNTIME_OUTPUT_DIRECTORY ${CURRENT_TEST_BINARY_DIR}
          )

  add_test(NAME ${case_name}
          COMMAND ${CURRENT_TEST_BINARY_DIR}/${case_name}
          )

  add_dependencies(${case_name} xecdaa)
endforeach()
