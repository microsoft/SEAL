# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(seal
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/aes.cpp
        ${CMAKE_CURRENT_LIST_DIR}/baseconverter.cpp
        ${CMAKE_CURRENT_LIST_DIR}/clipnormal.cpp
        ${CMAKE_CURRENT_LIST_DIR}/globals.cpp
        ${CMAKE_CURRENT_LIST_DIR}/hash.cpp
        ${CMAKE_CURRENT_LIST_DIR}/mempool.cpp
        ${CMAKE_CURRENT_LIST_DIR}/numth.cpp
        ${CMAKE_CURRENT_LIST_DIR}/polyarith.cpp
        ${CMAKE_CURRENT_LIST_DIR}/polyarithmod.cpp
        ${CMAKE_CURRENT_LIST_DIR}/polyarithsmallmod.cpp
        ${CMAKE_CURRENT_LIST_DIR}/rlwe.cpp
        ${CMAKE_CURRENT_LIST_DIR}/smallntt.cpp
        ${CMAKE_CURRENT_LIST_DIR}/uintarith.cpp
        ${CMAKE_CURRENT_LIST_DIR}/uintarithmod.cpp
        ${CMAKE_CURRENT_LIST_DIR}/uintarithsmallmod.cpp
        ${CMAKE_CURRENT_LIST_DIR}/uintcore.cpp
)

# Create the config file
configure_file(${CMAKE_CURRENT_LIST_DIR}/config.h.in ${CMAKE_CURRENT_LIST_DIR}/config.h)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/aes.h
        ${CMAKE_CURRENT_LIST_DIR}/baseconverter.h
        ${CMAKE_CURRENT_LIST_DIR}/clang.h
        ${CMAKE_CURRENT_LIST_DIR}/clipnormal.h
        ${CMAKE_CURRENT_LIST_DIR}/common.h
        ${CMAKE_CURRENT_LIST_DIR}/config.h
        ${CMAKE_CURRENT_LIST_DIR}/defines.h
        ${CMAKE_CURRENT_LIST_DIR}/gcc.h
        ${CMAKE_CURRENT_LIST_DIR}/globals.h
        ${CMAKE_CURRENT_LIST_DIR}/hash.h
        ${CMAKE_CURRENT_LIST_DIR}/hestdparms.h
        ${CMAKE_CURRENT_LIST_DIR}/locks.h
        ${CMAKE_CURRENT_LIST_DIR}/mempool.h
        ${CMAKE_CURRENT_LIST_DIR}/msvc.h
        ${CMAKE_CURRENT_LIST_DIR}/numth.h
        ${CMAKE_CURRENT_LIST_DIR}/pointer.h
        ${CMAKE_CURRENT_LIST_DIR}/polyarith.h
        ${CMAKE_CURRENT_LIST_DIR}/polyarithmod.h
        ${CMAKE_CURRENT_LIST_DIR}/polyarithsmallmod.h
        ${CMAKE_CURRENT_LIST_DIR}/polycore.h
        ${CMAKE_CURRENT_LIST_DIR}/rlwe.h
        ${CMAKE_CURRENT_LIST_DIR}/smallntt.h
        ${CMAKE_CURRENT_LIST_DIR}/uintarith.h
        ${CMAKE_CURRENT_LIST_DIR}/uintarithmod.h
        ${CMAKE_CURRENT_LIST_DIR}/uintarithsmallmod.h
        ${CMAKE_CURRENT_LIST_DIR}/uintcore.h
    DESTINATION
        ${SEAL_INCLUDES_INSTALL_DIR}/seal/util
)
