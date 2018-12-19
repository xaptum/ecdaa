# Copyright 2018 Xaptum, Inc.
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

################################################################################
# ecdaa
################################################################################

set(ECDAA_TOOL_SRC_INPUT_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/issuer_gen_keys_ZZZ.h
  ${CMAKE_CURRENT_SOURCE_DIR}/issuer_gen_keys_ZZZ.c
  ${CMAKE_CURRENT_SOURCE_DIR}/extract_gpk_ZZZ.h
  ${CMAKE_CURRENT_SOURCE_DIR}/extract_gpk_ZZZ.c
  ${CMAKE_CURRENT_SOURCE_DIR}/issuer_issue_credential_ZZZ.h
  ${CMAKE_CURRENT_SOURCE_DIR}/issuer_issue_credential_ZZZ.c
  ${CMAKE_CURRENT_SOURCE_DIR}/member_process_credential_ZZZ.h
  ${CMAKE_CURRENT_SOURCE_DIR}/member_process_credential_ZZZ.c
  ${CMAKE_CURRENT_SOURCE_DIR}/member_gen_keys_ZZZ.h
  ${CMAKE_CURRENT_SOURCE_DIR}/member_gen_keys_ZZZ.c
  ${CMAKE_CURRENT_SOURCE_DIR}/member_sign_ZZZ.h
  ${CMAKE_CURRENT_SOURCE_DIR}/member_sign_ZZZ.c
  ${CMAKE_CURRENT_SOURCE_DIR}/verify_ZZZ.h
  ${CMAKE_CURRENT_SOURCE_DIR}/verify_ZZZ.c
  )

foreach(template_file ${ECDAA_TOOL_SRC_INPUT_FILES})
  expand_template(${template_file} ECDAA_TOOL_SRCS FALSE FALSE)
endforeach()

set(ECDAA_TOOL_INPUT_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/ecdaa.c
  ${CMAKE_CURRENT_SOURCE_DIR}/parse_cli.c
  ${CMAKE_CURRENT_SOURCE_DIR}/parse_cli.h
  )

foreach(template_file ${ECDAA_TOOL_INPUT_FILES})
  expand_template(${template_file} ECDAA_TOOL_SRCS FALSE TRUE)
endforeach()

list(APPEND ECDAA_TOOL_SRCS
  ${CMAKE_CURRENT_SOURCE_DIR}/tool_rand.c
  )

set(ECDAA_TOOL_GENERATED_TOPLEVEL_INCLUDE_DIR "${TOPLEVEL_BINARY_DIR}/tool/")

add_executable(ecdaa-tool ${ECDAA_TOOL_SRCS})
set_target_properties(ecdaa-tool PROPERTIES OUTPUT_NAME ecdaa)

target_include_directories(ecdaa-tool PUBLIC
  $<BUILD_INTERFACE:${ECDAA_TOOL_GENERATED_TOPLEVEL_INCLUDE_DIR}>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  )

if(BUILD_SHARED_LIBS)
      target_link_libraries(ecdaa-tool PRIVATE ecdaa)
else()
      target_link_libraries(ecdaa-tool PRIVATE ecdaa_static)
endif()
install(TARGETS ecdaa-tool DESTINATION ${CMAKE_INSTALL_BINDIR})

set(CURRENT_TEST_BINARY_DIR ${CMAKE_BINARY_DIR}/tool/)

add_test(gen_keys ./ecdaa issuer genkeys)
add_test(extract_gpk ./ecdaa extractgpk)
add_test(gen_keys ./ecdaa member genkeys)
add_test(respond_to_request ./ecdaa issuer issuecredential)
add_test(process_issuer_response ./ecdaa member processcredential)
