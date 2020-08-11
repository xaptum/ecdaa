include(LibFindMacros)

# Use pkg-config to get hints about paths
libfind_pkg_check_modules(libtss2_PKGCONF libtss2-sys)

###############################################################################
# Find the include dirs
###############################################################################
find_path(libtss2_INCLUDE_DIR
  NAMES tss2/
  PATHS ${libtss2_sys_PKGCONF_INCLUDE_DIRS}
  )

###############################################################################
# TSS2-Sys Library
###############################################################################
find_library(libtss2_sys_LIBRARY
  NAMES tss2-sys
  PATHS ${libtss2_PKGCONFIG_LIBRARY_DIRS}
  )

set(libtss2_sys_PROCESS_INCLUDES libtss2_INCLUDE_DIR)
set(libtss2_sys_PROCESS_LIBS libtss2_sys_LIBRARY)

libfind_process(libtss2_sys)

if (libtss2_sys_FOUND)
  if (NOT TARGET tss2::sys)

    add_library(tss2::sys UNKNOWN IMPORTED)

    set_target_properties(tss2::sys PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${libtss2_INCLUDE_DIR}"
      IMPORTED_LINK_INTERFACE_LANGUAGES "C"
      IMPORTED_LOCATION "${libtss2_sys_LIBRARY}"
    )

  endif ()
endif ()

###############################################################################
# TSS2-TCTI-Device Library
###############################################################################
find_library(libtss2_tcti_device_LIBRARY
  NAMES tss2-tcti-device
  PATHS ${libtss2_PKGCONFIG_LIBRARY_DIRS}
  )

set(libtss2_tcti_device_PROCESS_INCLUDES libtss2_INCLUDE_DIR)
set(libtss2_tcti_device_PROCESS_LIBS libtss2_tcti_device_LIBRARY)

libfind_process(libtss2_tcti_device)

if (libtss2_tcti_device_FOUND)
  if (NOT TARGET tss2::tcti_device)

    add_library(tss2::tcti_device UNKNOWN IMPORTED)

    set_target_properties(tss2::tcti_device PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${libtss2_INCLUDE_DIR}"
      IMPORTED_LINK_INTERFACE_LANGUAGES "C"
      IMPORTED_LOCATION "${libtss2_tcti_device_LIBRARY}"
    )

  endif ()
endif ()

###############################################################################
# TSS2-TCTI-MSSIM Library
###############################################################################
find_library(libtss2_tcti_mssim_LIBRARY
  NAMES tss2-tcti-mssim
  PATHS ${libtss2_PKGCONFIG_LIBRARY_DIRS}
  )

set(libtss2_tcti_mssim_PROCESS_INCLUDES libtss2_INCLUDE_DIR)
set(libtss2_tcti_mssim_PROCESS_LIBS libtss2_tcti_mssim_LIBRARY)

libfind_process(libtss2_tcti_mssim)

if (libtss2_tcti_mssim_FOUND)
  if (NOT TARGET tss2::tcti_mssim)

    add_library(tss2::tcti_mssim UNKNOWN IMPORTED)

    set_target_properties(tss2::tcti_mssim PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${libtss2_INCLUDE_DIR}"
      IMPORTED_LINK_INTERFACE_LANGUAGES "C"
      IMPORTED_LOCATION "${libtss2_tcti_mssim_LIBRARY}"
    )

  endif ()
endif ()

###############################################################################
# Indicate package was found
###############################################################################
if (libtss2_sys_FOUND AND libtss2_tcti_device_FOUND AND libtss2_tcti_mssim_FOUND)
  set(TSS2_FOUND TRUE)
else()
  set(TSS2_FOUND FALSE)
endif()
