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
SET(ECDAA_TOOL_SRCS
        tool_rand.c
        ecdaa.c
        parse_cli.c
        ecdaa_extract_group_public_key.c
        ecdaa_issuer_create_group.c
        ecdaa_issuer_respond_to_join_request.c
        ecdaa_member_process_join_response.c
        ecdaa_member_request_join.c
        ecdaa_member_sign.c
        ecdaa_verify.c)

add_executable(ecdaa-tool ${ECDAA_TOOL_SRCS})
set_target_properties(ecdaa-tool PROPERTIES OUTPUT_NAME ecdaa)

target_link_libraries(ecdaa-tool PUBLIC AMCL::AMCL)
if(BUILD_SHARED_LIBS)
      target_link_libraries(ecdaa-tool PRIVATE ecdaa)
else()
      target_link_libraries(ecdaa-tool PRIVATE ecdaa_static)
endif()
install(TARGETS ecdaa-tool DESTINATION ${CMAKE_INSTALL_BINDIR})

set(CURRENT_TEST_BINARY_DIR ${CMAKE_BINARY_DIR}/tool/)

add_test(create_group ./ecdaa issuer creategroup)
add_test(extract_gpk ./ecdaa extractgpk)
add_test(request_join ./ecdaa member requestjoin)
add_test(respond_to_request ./ecdaa issuer respondtorequest)
add_test(process_issuer_response ./ecdaa member processresponse)
add_test(sign ./ecdaa member sign)
add_test(verify ./ecdaa verify)
