# Download and configure
if(SEAL_USE_ZSTD AND NOT MSVC)
    message(STATUS "Setting up Zstandard ...")
    if(NOT CMAKE_TOOLCHAIN_FILE)
        execute_process(
            COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
            OUTPUT_QUIET
            RESULT_VARIABLE result
            WORKING_DIRECTORY ${SEAL_THIRDPARTY_DIR}/zstd)
    else()
        seal_create_cache_entries(${SEAL_THIRDPARTY_DIR}/zstd)
        if(EXISTS ${SEAL_THIRDPARTY_DIR}/zstd/build/CMakeCache.txt)
            # Force regenerating make files. When cross compiling we might be
            # compiling more than one platform at a time.
            file(REMOVE ${SEAL_THIRDPARTY_DIR}/zstd/build/CMakeCache.txt)
        endif()
        execute_process(
            COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" . -Ccache_init.txt
            OUTPUT_QUIET
            RESULT_VARIABLE result
            WORKING_DIRECTORY ${SEAL_THIRDPARTY_DIR}/zstd)
    endif()
    if(result)
        message(WARNING "Failed to download ZSTD (${result}); disabling `SEAL_USE_ZSTD`")
    endif()
endif()

# Build
if(SEAL_USE_ZSTD AND NOT MSVC)
    execute_process(COMMAND ${CMAKE_COMMAND} --build .
        OUTPUT_QUIET
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${SEAL_THIRDPARTY_DIR}/zstd)
    if(result)
        message(WARNING "Failed to build ZSTD (${result}); disabling `SEAL_USE_ZSTD`")
    endif()
endif()

# Set up the targets
if(SEAL_USE_ZSTD AND NOT MSVC)
    add_subdirectory(
        ${SEAL_THIRDPARTY_DIR}/zstd/src/build/cmake
        EXCLUDE_FROM_ALL)

    # Set the ZSTD include directory
    set(SEAL_ZSTD_INCLUDE_DIR ${SEAL_THIRDPARTY_DIR}/zstd/src/lib)
endif()