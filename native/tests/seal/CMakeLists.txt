# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(sealtest
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/batchencoder.cpp
        ${CMAKE_CURRENT_LIST_DIR}/biguint.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ciphertext.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ckks.cpp
        ${CMAKE_CURRENT_LIST_DIR}/context.cpp
        ${CMAKE_CURRENT_LIST_DIR}/intencoder.cpp
        ${CMAKE_CURRENT_LIST_DIR}/encryptionparams.cpp
        ${CMAKE_CURRENT_LIST_DIR}/encryptor.cpp
        ${CMAKE_CURRENT_LIST_DIR}/evaluator.cpp
        ${CMAKE_CURRENT_LIST_DIR}/galoiskeys.cpp
        ${CMAKE_CURRENT_LIST_DIR}/intarray.cpp
        ${CMAKE_CURRENT_LIST_DIR}/keygenerator.cpp
        ${CMAKE_CURRENT_LIST_DIR}/memorymanager.cpp
        ${CMAKE_CURRENT_LIST_DIR}/modulus.cpp
        ${CMAKE_CURRENT_LIST_DIR}/plaintext.cpp
        ${CMAKE_CURRENT_LIST_DIR}/publickey.cpp
        ${CMAKE_CURRENT_LIST_DIR}/randomgen.cpp
        ${CMAKE_CURRENT_LIST_DIR}/randomtostd.cpp
        ${CMAKE_CURRENT_LIST_DIR}/relinkeys.cpp
        ${CMAKE_CURRENT_LIST_DIR}/secretkey.cpp
        ${CMAKE_CURRENT_LIST_DIR}/smallmodulus.cpp
)

add_subdirectory(util)
