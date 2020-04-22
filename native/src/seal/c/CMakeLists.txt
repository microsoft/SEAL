# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Source files in this directory
target_sources(sealc PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/batchencoder.cpp
    ${CMAKE_CURRENT_LIST_DIR}/biguint.cpp
    ${CMAKE_CURRENT_LIST_DIR}/ciphertext.cpp
    ${CMAKE_CURRENT_LIST_DIR}/ckksencoder.cpp
    ${CMAKE_CURRENT_LIST_DIR}/contextdata.cpp
    ${CMAKE_CURRENT_LIST_DIR}/decryptor.cpp
    # ${CMAKE_CURRENT_LIST_DIR}/dllmain.cpp
    ${CMAKE_CURRENT_LIST_DIR}/encryptionparameterqualifiers.cpp
    ${CMAKE_CURRENT_LIST_DIR}/encryptionparameters.cpp
    ${CMAKE_CURRENT_LIST_DIR}/encryptor.cpp
    ${CMAKE_CURRENT_LIST_DIR}/evaluator.cpp
    ${CMAKE_CURRENT_LIST_DIR}/galoiskeys.cpp
    ${CMAKE_CURRENT_LIST_DIR}/intencoder.cpp
    ${CMAKE_CURRENT_LIST_DIR}/keygenerator.cpp
    ${CMAKE_CURRENT_LIST_DIR}/kswitchkeys.cpp
    ${CMAKE_CURRENT_LIST_DIR}/memorymanager.cpp
    ${CMAKE_CURRENT_LIST_DIR}/memorypoolhandle.cpp
    ${CMAKE_CURRENT_LIST_DIR}/modulus.cpp
    ${CMAKE_CURRENT_LIST_DIR}/plaintext.cpp
    ${CMAKE_CURRENT_LIST_DIR}/publickey.cpp
    ${CMAKE_CURRENT_LIST_DIR}/relinkeys.cpp
    ${CMAKE_CURRENT_LIST_DIR}/sealcontext.cpp
    ${CMAKE_CURRENT_LIST_DIR}/secretkey.cpp
    ${CMAKE_CURRENT_LIST_DIR}/serialization.cpp
    ${CMAKE_CURRENT_LIST_DIR}/utilities.cpp
    ${CMAKE_CURRENT_LIST_DIR}/valcheck.cpp
    ${CMAKE_CURRENT_LIST_DIR}/version.cpp
)

# Add header files for installation
install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/batchencoder.h
        ${CMAKE_CURRENT_LIST_DIR}/biguint.h
        ${CMAKE_CURRENT_LIST_DIR}/ciphertext.h
        ${CMAKE_CURRENT_LIST_DIR}/ckksencoder.h
        ${CMAKE_CURRENT_LIST_DIR}/contextdata.h
        ${CMAKE_CURRENT_LIST_DIR}/decryptor.h
        ${CMAKE_CURRENT_LIST_DIR}/defines.h
        ${CMAKE_CURRENT_LIST_DIR}/encryptionparameterqualifiers.h
        ${CMAKE_CURRENT_LIST_DIR}/encryptionparameters.h
        ${CMAKE_CURRENT_LIST_DIR}/encryptor.h
        ${CMAKE_CURRENT_LIST_DIR}/evaluator.h
        ${CMAKE_CURRENT_LIST_DIR}/galoiskeys.h
        ${CMAKE_CURRENT_LIST_DIR}/intencoder.h
        ${CMAKE_CURRENT_LIST_DIR}/keygenerator.h
        ${CMAKE_CURRENT_LIST_DIR}/kswitchkeys.h
        ${CMAKE_CURRENT_LIST_DIR}/memorymanager.h
        ${CMAKE_CURRENT_LIST_DIR}/memorypoolhandle.h
        ${CMAKE_CURRENT_LIST_DIR}/modulus.h
        ${CMAKE_CURRENT_LIST_DIR}/plaintext.h
        ${CMAKE_CURRENT_LIST_DIR}/publickey.h
        ${CMAKE_CURRENT_LIST_DIR}/relinkeys.h
        ${CMAKE_CURRENT_LIST_DIR}/sealcontext.h
        ${CMAKE_CURRENT_LIST_DIR}/secretkey.h
        ${CMAKE_CURRENT_LIST_DIR}/serialization.h
        ${CMAKE_CURRENT_LIST_DIR}/stdafx.h
        ${CMAKE_CURRENT_LIST_DIR}/targetver.h
        ${CMAKE_CURRENT_LIST_DIR}/utilities.h
        ${CMAKE_CURRENT_LIST_DIR}/valcheck.h
        ${CMAKE_CURRENT_LIST_DIR}/version.h
    DESTINATION
        ${SEAL_INCLUDES_INSTALL_DIR}/seal/c
)
