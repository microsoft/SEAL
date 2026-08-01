#!/bin/bash

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

BASE_DIR=$(dirname "$0")
SEAL_ROOT_DIR=$BASE_DIR/../..

# Third-party sources are kept in their upstream formatting so they stay diffable
# against the original; clang-format would otherwise rewrite them wholesale. This list
# is the set of files under native/ that do not carry the Microsoft copyright header:
#   find native \( -name '*.h' -o -name '*.cpp' -o -name '*.c' \) \
#       -exec grep -L 'Copyright (c) Microsoft Corporation' {} +
# It intentionally covers extensions this script does not currently format, so that
# widening the glob below stays safe.
EXCLUDE_NAMES=(blake2.h blake2-impl.h blake2b.c blake2xb.c fips202.c)

exclude_args=()
for name in "${EXCLUDE_NAMES[@]}"; do
    exclude_args+=(-not -name "$name")
done

find "$SEAL_ROOT_DIR/native" \( -name '*.h' -o -name '*.cpp' \) "${exclude_args[@]}" -print0 \
    | xargs -0 clang-format -i
