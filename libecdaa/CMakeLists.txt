# Copyright 2017-2018 Xaptum, Inc.
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

set(ECDAA_INPUT_FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/include/ecdaa/credential_ZZZ.h
        ${CMAKE_CURRENT_SOURCE_DIR}/include/ecdaa/group_public_key_ZZZ.h
        ${CMAKE_CURRENT_SOURCE_DIR}/include/ecdaa/issuer_keypair_ZZZ.h
        ${CMAKE_CURRENT_SOURCE_DIR}/include/ecdaa/member_keypair_ZZZ.h
        ${CMAKE_CURRENT_SOURCE_DIR}/include/ecdaa/rand.h
        ${CMAKE_CURRENT_SOURCE_DIR}/include/ecdaa/revocations_ZZZ.h
        ${CMAKE_CURRENT_SOURCE_DIR}/include/ecdaa/signature_ZZZ.h

        ${CMAKE_CURRENT_SOURCE_DIR}/include/ecdaa/util/file_utils.h
        ${CMAKE_CURRENT_SOURCE_DIR}/include/ecdaa/util/rand_util.h
        ${CMAKE_CURRENT_SOURCE_DIR}/include/ecdaa/util/util_errors.h

        ${CMAKE_CURRENT_SOURCE_DIR}/credential_ZZZ.c
        ${CMAKE_CURRENT_SOURCE_DIR}/group_public_key_ZZZ.c
        ${CMAKE_CURRENT_SOURCE_DIR}/issuer_keypair_ZZZ.c
        ${CMAKE_CURRENT_SOURCE_DIR}/member_keypair_ZZZ.c
        ${CMAKE_CURRENT_SOURCE_DIR}/signature_ZZZ.c

        ${CMAKE_CURRENT_SOURCE_DIR}/util/file_utils.c
        ${CMAKE_CURRENT_SOURCE_DIR}/util/rand_util.c
        ${CMAKE_CURRENT_SOURCE_DIR}/schnorr/schnorr_ZZZ.h
        ${CMAKE_CURRENT_SOURCE_DIR}/schnorr/schnorr_ZZZ.c
        )

foreach(template_file ${ECDAA_INPUT_FILES})
        expand_template(${template_file} ECDAA_SRCS FALSE)
endforeach()

set(ECDAA_GENERATED_TOPLEVEL_INCLUDE_DIR "${TOPLEVEL_BINARY_DIR}/libecdaa/include")

add_custom_target(toplevel_header
        COMMAND python3 ${PROJECT_SOURCE_DIR}/cmake/template_expansion.py
                        --template ${CMAKE_CURRENT_SOURCE_DIR}/include/ecdaa.h
                        --word-size ${WORD_SIZE}
                        --curves ${ECDAA_CURVES}
                        --out-dir ${TOPLEVEL_BINARY_DIR}
                        --top-level-dir ${PROJECT_SOURCE_DIR}
                        --top-level-header)

################################################################################
# Shared Libary
################################################################################
if (BUILD_SHARED_LIBS)
        add_library(ecdaa SHARED ${ECDAA_SRCS} $<TARGET_OBJECTS:ecdaa_utilities>)

        set_target_properties(ecdaa PROPERTIES
                VERSION "${ECDAA_VERSION}"
                SOVERSION "${ECDAA_SOVERSION}"
        )

        target_include_directories(ecdaa PUBLIC
                $<BUILD_INTERFACE:${ECDAA_GENERATED_TOPLEVEL_INCLUDE_DIR}>
                $<BUILD_INTERFACE:${ECDAA_INTERNAL_UTILITIES_INCLUDE_DIR}>
                $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        )

        target_link_libraries(ecdaa
          PUBLIC  AMCL::AMCL
          PRIVATE ${ECDAA_SEED_LIBRARY}
        )

        install(TARGETS ecdaa
                EXPORT ecdaa-targets
                RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
                LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
                ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        )

        add_dependencies(ecdaa toplevel_header)
endif ()

################################################################################
# Static Libary
################################################################################
# If also building shared, add a suffix to target to avoid conflict
if (BUILD_SHARED_LIBS)
  set(STATIC_TARGET "ecdaa_static")
else()
  set(STATIC_TARGET "ecdaa")
endif()

if (BUILD_STATIC_LIBS)
        add_library(${STATIC_TARGET} STATIC ${ECDAA_SRCS} $<TARGET_OBJECTS:ecdaa_utilities>)

        set_target_properties(${STATIC_TARGET} PROPERTIES
                OUTPUT_NAME "ecdaa${STATIC_SUFFIX}"
                VERSION "${ECDAA_VERSION}"
                SOVERSION "${ECDAA_SOVERSION}"
        )

        target_include_directories(${STATIC_TARGET} PUBLIC
                $<BUILD_INTERFACE:${ECDAA_GENERATED_TOPLEVEL_INCLUDE_DIR}>
                $<BUILD_INTERFACE:${ECDAA_INTERNAL_UTILITIES_INCLUDE_DIR}>
                $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        )

        target_link_libraries(${STATIC_TARGET}
          PUBLIC  AMCL::AMCL
          PRIVATE ${ECDAA_SEED_LIBRARY}
        )

        install(TARGETS ${STATIC_TARGET}
                EXPORT ecdaa-targets
                RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
                LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
                ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        )

        add_dependencies(${STATIC_TARGET} toplevel_header)
endif ()

# If not building shared, add an alias with the suffixed variant
if (NOT BUILD_SHARED_LIBS)
  add_library(ecdaa_static ALIAS ecdaa)
endif()

################################################################################
# Headers
################################################################################
install(DIRECTORY ${ECDAA_GENERATED_TOPLEVEL_INCLUDE_DIR}/ecdaa
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

install(FILES ${ECDAA_GENERATED_TOPLEVEL_INCLUDE_DIR}/ecdaa.h
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

################################################################################
# pkgconfig
################################################################################
configure_file(${PROJECT_SOURCE_DIR}/ecdaa.pc.in ecdaa.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/ecdaa.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)
