# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

find_path(BCrypt_INCLUDE_DIR
    NAMES bcrypt.h
    PATHS ${env.INCLUDE})

find_library(BCrypt_LIBRARY
    NAMES bcrypt.lib
    PATHS ${env.LIB})

find_package(PackageHandleStandardArgs)

find_package_handle_standard_args(BCrypt
    FOUND_VAR BCrypt_FOUND
    REQUIRED_VARS BCrypt_LIBRARY BCrypt_INCLUDE_DIR)

if(BCrypt_FOUND AND NOT TARGET BCrypt::bcrypt)
    set(CMAKE_REQUIRED_INCLUDES ${BCrypt_INCLUDE_DIR})
    add_library(BCrypt::bcrypt UNKNOWN IMPORTED)
    set_target_properties(BCrypt::bcrypt PROPERTIES
        IMPORTED_LOCATION ${BCrypt_LIBRARY}
        INTERFACE_INCLUDE_DIRECTORIES ${BCrypt_INCLUDE_DIR})
endif()