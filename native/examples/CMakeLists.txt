# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(sealexamples
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/examples.cpp
        ${CMAKE_CURRENT_LIST_DIR}/1_bfv_basics.cpp
        ${CMAKE_CURRENT_LIST_DIR}/2_encoders.cpp
        ${CMAKE_CURRENT_LIST_DIR}/3_levels.cpp
        ${CMAKE_CURRENT_LIST_DIR}/4_ckks_basics.cpp
        ${CMAKE_CURRENT_LIST_DIR}/5_rotation.cpp
        ${CMAKE_CURRENT_LIST_DIR}/6_serialization.cpp
        ${CMAKE_CURRENT_LIST_DIR}/7_performance.cpp
)