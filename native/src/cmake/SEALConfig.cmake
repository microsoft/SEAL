# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Exports target SEAL::seal
#
# Creates variables:
#   SEAL_FOUND : If Microsoft SEAL and all required dependencies were found
#   SEAL_BUILD_TYPE : The build configuration used
#   SEAL_DEBUG : Set to non-zero value if library is compiled with extra debugging code (very slow!)
#   SEAL_LIB_BUILD_TYPE : Set to either "Static", "Static_PIC", or "Shared" depending on library build type
#   SEAL_USE_CXX17 : Set to non-zero value if library is compiled as C++17 instead of C++14
#   SEAL_ENFORCE_HE_STD_SECURITY : Set to non-zero value if library is compiled to enforce at least
#       a 128-bit security level based on HomomorphicEncryption.org security estimates
#   SEAL_USE_MSGSL : Set to non-zero value if library is compiled with Microsoft GSL support
#   SEAL_USE_ZLIB : Set to non-zero value if library is compiled with zlib support
#   MSGSL_INCLUDE_DIR : Holds the path to Microsoft GSL if library is compiled with Microsoft GSL support


####### Expanded from @PACKAGE_INIT@ by configure_package_config_file() #######
####### Any changes to this file will be overwritten by the next CMake run ####
####### The input file was SEALConfig.cmake.in                            ########

get_filename_component(PACKAGE_PREFIX_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../" ABSOLUTE)

macro(set_and_check _var _file)
  set(${_var} "${_file}")
  if(NOT EXISTS "${_file}")
    message(FATAL_ERROR "File or directory ${_file} referenced by variable ${_var} does not exist !")
  endif()
endmacro()

macro(check_required_components _NAME)
  foreach(comp ${${_NAME}_FIND_COMPONENTS})
    if(NOT ${_NAME}_${comp}_FOUND)
      if(${_NAME}_FIND_REQUIRED_${comp})
        set(${_NAME}_FOUND FALSE)
      endif()
    endif()
  endforeach()
endmacro()

####################################################################################

include(CMakeFindDependencyMacro)

macro(warning_when_not_quiet msg)
    if(NOT SEAL_FIND_QUIETLY)
        message(WARNING ${msg})
    endif()
endmacro()

macro(status_when_not_quiet msg)
    if(NOT SEAL_FIND_QUIETLY)
        message(STATUS ${msg})
    endif()
endmacro()

macro(find_seal_dependency dep)
    find_dependency(${dep})
    if(NOT ${dep}_FOUND)
        warning_when_not_quiet("Could not find dependency `${dep}` required by this configuration")
        set(SEAL_FOUND FALSE)
        return()
    endif()
endmacro()

set(SEAL_FOUND FALSE)

set(SEAL_BUILD_TYPE Release)
set(SEAL_DEBUG OFF)
set(SEAL_LIB_BUILD_TYPE Static_PIC)
set(SEAL_USE_CXX17 ON)
set(SEAL_ENFORCE_HE_STD_SECURITY )

# Add the current directory to the module search path
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR})

set(SEAL_USE_MSGSL OFF)
if(SEAL_USE_MSGSL)
    find_seal_dependency(MSGSL)
endif()

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_seal_dependency(Threads)

set(SEAL_USE_ZLIB ON)
if(SEAL_USE_ZLIB)
    find_seal_dependency(ZLIB)
endif()

include(${CMAKE_CURRENT_LIST_DIR}/SEALTargets.cmake)

if(TARGET SEAL::seal)
    status_when_not_quiet("Microsoft SEAL -> Version ${SEAL_VERSION} detected")
    if(SEAL_DEBUG)
        status_when_not_quiet("Performance warning: Microsoft SEAL compiled in debug mode")
    endif()
    status_when_not_quiet("Microsoft SEAL -> Library build type: ${SEAL_LIB_BUILD_TYPE}")
    set(SEAL_FOUND TRUE)
else()
    warning_when_not_quiet("Microsoft SEAL -> NOT FOUND")
    set(SEAL_FOUND FALSE)
endif()

