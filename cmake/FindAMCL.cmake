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

if (NOT TARGET amcl)
        if (NOT AMCL_LOCAL_DIR)
                set(AMCL_LOCAL_DIR "${CMAKE_CURRENT_LIST_DIR}/../milagro-crypto-c/install/")
        endif (NOT AMCL_LOCAL_DIR)

        if (NOT FORCE_SYSTEM_AMCL_LIB)
                set(AMCL_INCLUDE_DIRS "${AMCL_LOCAL_DIR}/include/")
                set(AMCL_LIB_DIRS "${AMCL_LOCAL_DIR}/lib/")
        endif (NOT FORCE_SYSTEM_AMCL_LIB)

        string(REPLACE "," ";" curves "${ECDAA_CURVES}")
        foreach(curve ${curves})
                find_library(AMCL_CURVE_${curve}_LIBRARY
                             NAMES amcl_curve_${curve}
                             HINTS ${AMCL_LIB_DIRS})
                list(APPEND AMCL_CURVE_LIBRARIES ${AMCL_CURVE_${curve}_LIBRARY})

                find_library(AMCL_PAIRING_${curve}_LIBRARY
                             NAMES amcl_pairing_${curve}
                             HINTS ${AMCL_LIB_DIRS})
                list(APPEND AMCL_CURVE_LIBRARIES ${AMCL_PAIRING_${curve}_LIBRARY})
        endforeach(curve ${curves})

        find_library(AMCL_CORE_LIBRARY
                     NAMES amcl_core
                     HINTS ${AMCL_LIB_DIRS})

        set(AMCL_LIBRARIES ${AMCL_CURVE_LIBRARIES} ${AMCL_CORE_LIBRARY})

        set(AMCL_FOUND TRUE)
endif (NOT TARGET amcl)
