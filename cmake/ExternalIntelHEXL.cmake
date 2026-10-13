# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

FetchContent_Declare(
    hexl
    PREFIX hexl
    GIT_REPOSITORY https://github.com/IntelLabs/hexl
    GIT_TAG 75a60b8cc908fb4c166315dd8b55b2e1ee7faea7 # 1.2.6
)
FetchContent_GetProperties(hexl)

if(NOT hexl_POPULATED)
    FetchContent_Populate(hexl)
    set(CMAKE_C_COMPILER ${CMAKE_C_COMPILER} CACHE STRING "" FORCE)
    set(CMAKE_CXX_COMPILER ${CMAKE_CXX_COMPILER} CACHE STRING "" FORCE)
    set(CMAKE_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX} CACHE STRING "" FORCE)
    set(HEXL_BENCHMARK OFF CACHE BOOL "" FORCE)
    set(HEXL_COVERAGE OFF CACHE BOOL "" FORCE)
    set(HEXL_TESTING OFF CACHE BOOL "" FORCE)
    set(HEXL_SHARED_LIB ${BUILD_SHARED_LIBS} CACHE BOOL "" FORCE)
    set(EXCLUDE_FROM_ALL TRUE)

    mark_as_advanced(BUILD_HEXL)
    mark_as_advanced(INSTALL_HEXL)
    mark_as_advanced(FETCHCONTENT_SOURCE_DIR_HEXL)
    mark_as_advanced(FETCHCONTENT_UPDATES_DISCONNECTED_HEXL)

    # Intel HEXL builds google/cpu_features, which requires CMake 3.0. CMake 4 removed compatibility with versions
    # older than 3.5, so configure Intel HEXL and its dependencies with the policies of CMake 3.5.
    if(CMAKE_VERSION VERSION_GREATER_EQUAL 4.0 AND NOT DEFINED CMAKE_POLICY_VERSION_MINIMUM)
        set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
        set(SEAL_HEXL_POLICY_VERSION_MINIMUM_SET ON)
    endif()

    add_subdirectory(
        ${hexl_SOURCE_DIR}
        ${hexl_SOURCE_DIR}/../hexl-build
        EXCLUDE_FROM_ALL
    )

    if(SEAL_HEXL_POLICY_VERSION_MINIMUM_SET)
        unset(CMAKE_POLICY_VERSION_MINIMUM)
        unset(SEAL_HEXL_POLICY_VERSION_MINIMUM_SET)
    endif()
endif()
