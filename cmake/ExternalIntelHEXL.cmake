# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

FetchContent_Declare(
    hexl
    PREFIX hexl
    GIT_REPOSITORY https://github.com/intel/hexl.git
    GIT_TAG v1.0.1
)
FetchContent_GetProperties(hexl)

if(NOT hexl_POPULATED)
    FetchContent_Populate(hexl)
    set(HEXL_DEBUG OFF) # Set to ON/OFF to toggle debugging

    set(CMAKE_C_COMPILER ${CMAKE_C_COMPILER} CACHE STRING "" FORCE)
    set(CMAKE_CXX_COMPILER ${CMAKE_CXX_COMPILER} CACHE STRING "" FORCE)
    set(CMAKE_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX} CACHE STRING "" FORCE)
    set(HEXL_DEBUG ${HEXL_DEBUG} CACHE BOOL "" FORCE)
    set(HEXL_BENCHMARK OFF CACHE BOOL "" FORCE)
    set(HEXL_EXPORT OFF CACHE BOOL "" FORCE)
    set(HEXL_COVERAGE OFF CACHE BOOL "" FORCE)
    set(HEXL_TESTING OFF CACHE BOOL "" FORCE)
    set(HEXL_SHARED_LIB OFF CACHE BOOL "" FORCE)
    set(EXCLUDE_FROM_ALL TRUE)

    mark_as_advanced(BUILD_HEXL)
    mark_as_advanced(INSTALL_HEXL)
    mark_as_advanced(FETCHCONTENT_SOURCE_DIR_HEXL)
    mark_as_advanced(FETCHCONTENT_UPDATES_DISCONNECTED_HEXL)

    add_subdirectory(
        ${hexl_SOURCE_DIR}
        EXCLUDE_FROM_ALL
    )
endif()
