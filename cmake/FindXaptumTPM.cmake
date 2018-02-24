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

if (NOT TARGET xaptumtpm)
        if (NOT XAPTUM_TPM_LOCAL_DIR)
                set(XAPTUM_TPM_LOCAL_DIR "${CMAKE_CURRENT_LIST_DIR}/../xaptum-tpm")
        endif (NOT XAPTUM_TPM_LOCAL_DIR)

        if (NOT FORCE_SYSTEM_XAPTUM_TPM_LIB)
                set(XAPTUM_TPM_INCLUDE_DIRS "${XAPTUM_TPM_LOCAL_DIR}/include/")
                set(XAPTUM_TPM_LIB_DIRS "${XAPTUM_TPM_LOCAL_DIR}/build/")
        endif (NOT FORCE_SYSTEM_XAPTUM_TPM_LIB)

        find_library(XAPTUM_TPM_LIBRARY
                     NAMES xaptum-tpm xaptum-tpm_static
                     HINTS ${XAPTUM_TPM_LIB_DIRS})
        set(XAPTUM_TPM_LIBRARIES ${XAPTUM_TPM_LIBRARY})

        set(XAPTUM_TPM_FOUND TRUE)
endif (NOT TARGET xaptumtpm)
