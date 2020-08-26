# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Source files in this directory
target_sources(seal_obj PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/blake2b.c
    ${CMAKE_CURRENT_LIST_DIR}/blake2xb.c
    ${CMAKE_CURRENT_LIST_DIR}/clipnormal.cpp
    ${CMAKE_CURRENT_LIST_DIR}/common.cpp
    ${CMAKE_CURRENT_LIST_DIR}/croots.cpp
    ${CMAKE_CURRENT_LIST_DIR}/globals.cpp
    ${CMAKE_CURRENT_LIST_DIR}/galois.cpp
    ${CMAKE_CURRENT_LIST_DIR}/hash.cpp
    ${CMAKE_CURRENT_LIST_DIR}/iterator.cpp
    ${CMAKE_CURRENT_LIST_DIR}/mempool.cpp
    ${CMAKE_CURRENT_LIST_DIR}/numth.cpp
    ${CMAKE_CURRENT_LIST_DIR}/polyarithsmallmod.cpp
    ${CMAKE_CURRENT_LIST_DIR}/rlwe.cpp
    ${CMAKE_CURRENT_LIST_DIR}/rns.cpp
    ${CMAKE_CURRENT_LIST_DIR}/scalingvariant.cpp
    ${CMAKE_CURRENT_LIST_DIR}/ntt.cpp
    ${CMAKE_CURRENT_LIST_DIR}/streambuf.cpp
    ${CMAKE_CURRENT_LIST_DIR}/uintarith.cpp
    ${CMAKE_CURRENT_LIST_DIR}/uintarithmod.cpp
    ${CMAKE_CURRENT_LIST_DIR}/uintarithsmallmod.cpp
    ${CMAKE_CURRENT_LIST_DIR}/uintcore.cpp
    ${CMAKE_CURRENT_LIST_DIR}/ztools.cpp
)

# Create the config file
configure_file(${CMAKE_CURRENT_LIST_DIR}/config.h.in ${CMAKE_CURRENT_LIST_DIR}/config.h)

# Add header files for installation
install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/blake2.h
        ${CMAKE_CURRENT_LIST_DIR}/blake2-impl.h
        ${CMAKE_CURRENT_LIST_DIR}/clang.h
        ${CMAKE_CURRENT_LIST_DIR}/clipnormal.h
        ${CMAKE_CURRENT_LIST_DIR}/common.h
        ${CMAKE_CURRENT_LIST_DIR}/config.h
        ${CMAKE_CURRENT_LIST_DIR}/croots.h
        ${CMAKE_CURRENT_LIST_DIR}/defines.h
        ${CMAKE_CURRENT_LIST_DIR}/galois.h
        ${CMAKE_CURRENT_LIST_DIR}/gcc.h
        ${CMAKE_CURRENT_LIST_DIR}/globals.h
        ${CMAKE_CURRENT_LIST_DIR}/hash.h
        ${CMAKE_CURRENT_LIST_DIR}/hestdparms.h
        ${CMAKE_CURRENT_LIST_DIR}/iterator.h
        ${CMAKE_CURRENT_LIST_DIR}/locks.h
        ${CMAKE_CURRENT_LIST_DIR}/mempool.h
        ${CMAKE_CURRENT_LIST_DIR}/msvc.h
        ${CMAKE_CURRENT_LIST_DIR}/numth.h
        ${CMAKE_CURRENT_LIST_DIR}/pointer.h
        ${CMAKE_CURRENT_LIST_DIR}/polyarithsmallmod.h
        ${CMAKE_CURRENT_LIST_DIR}/polycore.h
        ${CMAKE_CURRENT_LIST_DIR}/rlwe.h
        ${CMAKE_CURRENT_LIST_DIR}/rns.h
        ${CMAKE_CURRENT_LIST_DIR}/scalingvariant.h
        ${CMAKE_CURRENT_LIST_DIR}/ntt.h
        ${CMAKE_CURRENT_LIST_DIR}/streambuf.h
        ${CMAKE_CURRENT_LIST_DIR}/uintarith.h
        ${CMAKE_CURRENT_LIST_DIR}/uintarithmod.h
        ${CMAKE_CURRENT_LIST_DIR}/uintarithsmallmod.h
        ${CMAKE_CURRENT_LIST_DIR}/uintcore.h
        ${CMAKE_CURRENT_LIST_DIR}/ztools.h
    DESTINATION
        ${SEAL_INCLUDES_INSTALL_DIR}/seal/util
)
