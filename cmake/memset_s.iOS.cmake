# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# This cache-initialization file will be used to enable memset_s when cross-compiling
# for iOS, as check_cxx_source_runs fails for cross-compilers.

set(SEAL_MEMSET_S_FOUND_EXITCODE
    "0"
    CACHE STRING "Result from TRY_RUN" FORCE)

set(SEAL_MEMSET_S_FOUND_EXITCODE__TRYRUN_OUTPUT
    ""
    CACHE STRING "Output from TRY_RUN" FORCE)
