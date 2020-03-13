#!/bin/bash

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

BASE_DIR=$(dirname "$0")
SEAL_ROOT_DIR=$BASE_DIR/../../
shopt -s globstar
clang-format -i $SEAL_ROOT_DIR/native/**/*.h
clang-format -i $SEAL_ROOT_DIR/native/**/*.cpp