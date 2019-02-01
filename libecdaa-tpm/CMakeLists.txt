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

set(ECDAA_TPM_INPUT_FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/include/ecdaa-tpm/member_keypair_TPM_ZZZ.h
        ${CMAKE_CURRENT_SOURCE_DIR}/include/ecdaa-tpm/signature_TPM_ZZZ.h

        ${CMAKE_CURRENT_SOURCE_DIR}/member_keypair_TPM_ZZZ.c
        ${CMAKE_CURRENT_SOURCE_DIR}/signature_TPM_ZZZ.c

        ${CMAKE_CURRENT_SOURCE_DIR}/tpm/commit_ZZZ.h
        ${CMAKE_CURRENT_SOURCE_DIR}/tpm/commit_ZZZ.c
        ${CMAKE_CURRENT_SOURCE_DIR}/schnorr-tpm/schnorr_TPM_ZZZ.h
        ${CMAKE_CURRENT_SOURCE_DIR}/schnorr-tpm/schnorr_TPM_ZZZ.c
        )

foreach(template_file ${ECDAA_TPM_INPUT_FILES})
        expand_template(${template_file} ECDAA_TPM_SRCS TRUE FALSE)
endforeach()

list(APPEND ECDAA_TPM_SRCS
        ${CMAKE_CURRENT_SOURCE_DIR}/tpm_context.c
        ${CMAKE_CURRENT_SOURCE_DIR}/tpm/sign.c
        )

set(ECDAA_TPM_GENERATED_TOPLEVEL_INCLUDE_DIR "${TOPLEVEL_BINARY_DIR}/libecdaa-tpm/include")

add_custom_target(ecdaa_tpm_toplevel_header
        COMMAND python3 ${PROJECT_SOURCE_DIR}/cmake/template_expansion.py
                        --template ${CMAKE_CURRENT_SOURCE_DIR}/include/ecdaa-tpm.h
                        --word-size ${WORD_SIZE}
                        --curves ${ECDAA_CURVES}
                        --out-dir ${TOPLEVEL_BINARY_DIR}
                        --top-level-dir ${PROJECT_SOURCE_DIR}
                        --top-level-header
                        --use-tpm)

################################################################################
# Shared Libary
################################################################################
if (BUILD_SHARED_LIBS)
        add_library(ecdaa-tpm SHARED ${ECDAA_TPM_SRCS} $<TARGET_OBJECTS:ecdaa_utilities>)

        set_target_properties(ecdaa-tpm PROPERTIES
                VERSION "${ECDAA_VERSION}"
                SOVERSION "${ECDAA_SOVERSION}"
        )

        target_include_directories(ecdaa-tpm PUBLIC
                $<BUILD_INTERFACE:${ECDAA_TPM_GENERATED_TOPLEVEL_INCLUDE_DIR}>
                $<BUILD_INTERFACE:${ECDAA_INTERNAL_UTILITIES_INCLUDE_DIR}>
                $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
                $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        )

        target_link_libraries(ecdaa-tpm
          PUBLIC ecdaa
          PUBLIC xaptum-tpm::xaptum-tpm 
          PUBLIC AMCL::AMCL
        )

        install(TARGETS ecdaa-tpm
                EXPORT ecdaa-targets
                RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
                LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
                ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        )

        add_dependencies(ecdaa-tpm ecdaa_tpm_toplevel_header)
endif ()

################################################################################
# Static Libary
################################################################################
# If also building shared, add a suffix to target to avoid conflict
if (BUILD_SHARED_LIBS)
  set(STATIC_TARGET "ecdaa-tpm_static")
else()
  set(STATIC_TARGET "ecdaa-tpm")
endif()

if (BUILD_STATIC_LIBS)
        add_library(${STATIC_TARGET} STATIC ${ECDAA_TPM_SRCS} $<TARGET_OBJECTS:ecdaa_utilities>)

        set_target_properties(${STATIC_TARGET} PROPERTIES
                OUTPUT_NAME "ecdaa-tpm${STATIC_SUFFIX}"
                VERSION "${ECDAA_VERSION}"
                SOVERSION "${ECDAA_SOVERSION}"
        )

        target_include_directories(${STATIC_TARGET} PUBLIC
                $<BUILD_INTERFACE:${ECDAA_TPM_GENERATED_TOPLEVEL_INCLUDE_DIR}>
                $<BUILD_INTERFACE:${ECDAA_INTERNAL_UTILITIES_INCLUDE_DIR}>
                $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
                $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        )

        target_link_libraries(${STATIC_TARGET}
          PUBLIC ecdaa_static
          PUBLIC xaptum-tpm::xaptum-tpm
          PUBLIC AMCL::AMCL
        )

        install(TARGETS ${STATIC_TARGET}
                EXPORT ecdaa-targets
                RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
                LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
                ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        )

        add_dependencies(${STATIC_TARGET} ecdaa_tpm_toplevel_header)
endif ()

# If not building shared, add an alias with the suffixed variant
if (NOT BUILD_SHARED_LIBS)
  add_library(ecdaa-tpm_static ALIAS ecdaa-tpm)
endif()

################################################################################
# Headers
################################################################################
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/ecdaa-tpm
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
        PATTERN "*_ZZZ.h" EXCLUDE
)

install(DIRECTORY ${ECDAA_TPM_GENERATED_TOPLEVEL_INCLUDE_DIR}/ecdaa-tpm
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

install(FILES ${ECDAA_TPM_GENERATED_TOPLEVEL_INCLUDE_DIR}/ecdaa-tpm.h
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

################################################################################
# pkgconfig
################################################################################
configure_file(${PROJECT_SOURCE_DIR}/ecdaa-tpm.pc.in ecdaa-tpm.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/ecdaa-tpm.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)
