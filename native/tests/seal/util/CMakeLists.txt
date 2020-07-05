# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(sealtest
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/clipnormal.cpp
        ${CMAKE_CURRENT_LIST_DIR}/common.cpp
        ${CMAKE_CURRENT_LIST_DIR}/galois.cpp
        ${CMAKE_CURRENT_LIST_DIR}/hash.cpp
        ${CMAKE_CURRENT_LIST_DIR}/iterator.cpp
        ${CMAKE_CURRENT_LIST_DIR}/locks.cpp
        ${CMAKE_CURRENT_LIST_DIR}/mempool.cpp
        ${CMAKE_CURRENT_LIST_DIR}/numth.cpp
        ${CMAKE_CURRENT_LIST_DIR}/polyarithsmallmod.cpp
        ${CMAKE_CURRENT_LIST_DIR}/polycore.cpp
        ${CMAKE_CURRENT_LIST_DIR}/rns.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ntt.cpp
        ${CMAKE_CURRENT_LIST_DIR}/stringtouint64.cpp
        ${CMAKE_CURRENT_LIST_DIR}/uint64tostring.cpp
        ${CMAKE_CURRENT_LIST_DIR}/uintarith.cpp
        ${CMAKE_CURRENT_LIST_DIR}/uintarithmod.cpp
        ${CMAKE_CURRENT_LIST_DIR}/uintarithsmallmod.cpp
        ${CMAKE_CURRENT_LIST_DIR}/uintcore.cpp
)
