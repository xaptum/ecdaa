if(NOT TARGET ecdaa)
        if(NOT ECDAA_DIR)
                set(ECDAA_DIR "${CMAKE_CURRENT_LIST_DIR}/../../ecdaa") 
        endif(NOT ECDAA_DIR)
        add_subdirectory(${ECDAA_DIR})
endif()

set(ECDAA_FOUND TRUE)
