# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(sealnetnative
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/batchencoder_wrapper.cpp
        ${CMAKE_CURRENT_LIST_DIR}/biguint_wrapper.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ciphertext_wrapper.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ckksencoder_wrapper.cpp
        ${CMAKE_CURRENT_LIST_DIR}/contextdata_wrapper.cpp
        ${CMAKE_CURRENT_LIST_DIR}/decryptor_wrapper.cpp
        ${CMAKE_CURRENT_LIST_DIR}/encryptionparameterqualifiers_wrapper.cpp
        ${CMAKE_CURRENT_LIST_DIR}/encryptionparameters_wrapper.cpp
        ${CMAKE_CURRENT_LIST_DIR}/encryptor_wrapper.cpp
        ${CMAKE_CURRENT_LIST_DIR}/evaluator_wrapper.cpp
        ${CMAKE_CURRENT_LIST_DIR}/galoiskeys_wrapper.cpp
        ${CMAKE_CURRENT_LIST_DIR}/intencoder_wrapper.cpp
        ${CMAKE_CURRENT_LIST_DIR}/keygenerator_wrapper.cpp
        ${CMAKE_CURRENT_LIST_DIR}/kswitchkeys_wrapper.cpp
        ${CMAKE_CURRENT_LIST_DIR}/memorymanager_wrapper.cpp
        ${CMAKE_CURRENT_LIST_DIR}/memorypoolhandle_wrapper.cpp
        ${CMAKE_CURRENT_LIST_DIR}/modulus_wrapper.cpp
        ${CMAKE_CURRENT_LIST_DIR}/plaintext_wrapper.cpp
        ${CMAKE_CURRENT_LIST_DIR}/publickey_wrapper.cpp
        ${CMAKE_CURRENT_LIST_DIR}/relinkeys_wrapper.cpp
        ${CMAKE_CURRENT_LIST_DIR}/sealcontext_wrapper.cpp
        ${CMAKE_CURRENT_LIST_DIR}/secretkey_wrapper.cpp
        ${CMAKE_CURRENT_LIST_DIR}/smallmodulus_wrapper.cpp
        ${CMAKE_CURRENT_LIST_DIR}/utilities.cpp
        ${CMAKE_CURRENT_LIST_DIR}/valcheck_wrapper.cpp
)