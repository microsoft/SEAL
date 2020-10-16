# ZLIB has no VERSION given to project(), needs to suppress CMP0048 warning
if(SEAL_USE_ZLIB AND NOT MSVC)
    set(CMAKE_SUPPRESS_DEVELOPER_WARNINGS TRUE CACHE INTERNAL "Suppress CMP0048 warning" FORCE)
endif()

# Download and configure
if(SEAL_USE_ZLIB AND NOT MSVC)
    message(STATUS "Setting up ZLIB ...")
    if(NOT CMAKE_TOOLCHAIN_FILE)
        execute_process(
            COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
            OUTPUT_QUIET
            RESULT_VARIABLE result
            WORKING_DIRECTORY ${SEAL_THIRDPARTY_DIR}/zlib)
    else()
        seal_create_cache_entries(${SEAL_THIRDPARTY_DIR}/zlib)
        if(EXISTS ${SEAL_THIRDPARTY_DIR}/zlib/build/CMakeCache.txt)
            # Force regenerating make files. When cross compiling we might be
            # compiling more than one platform at a time.
            file(REMOVE ${SEAL_THIRDPARTY_DIR}/zlib/build/CMakeCache.txt)
        endif()
        execute_process(
            COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" . -Ccache_init.txt
            OUTPUT_QUIET
            RESULT_VARIABLE result
            WORKING_DIRECTORY ${SEAL_THIRDPARTY_DIR}/zlib)
    endif()
    if(result)
        message(WARNING "Failed to download ZLIB (${result}); disabling `SEAL_USE_ZLIB`")
    endif()
    mark_as_advanced(AMD64)
    mark_as_advanced(ASM686)
    mark_as_advanced(EXECUTABLE_OUTPUT_PATH)
    mark_as_advanced(CMAKE_INSTALL_PREFIX)
    mark_as_advanced(INSTALL_BIN_DIR)
    mark_as_advanced(INSTALL_INC_DIR)
    mark_as_advanced(INSTALL_LIB_DIR)
    mark_as_advanced(INSTALL_MAN_DIR)
    mark_as_advanced(INSTALL_PKGCONFIG_DIR)
    mark_as_advanced(LIBRARY_OUTPUT_PATH)
    mark_as_advanced(CMAKE_BACKWARDS_COMPATIBILITY)
endif()

# Build
if(SEAL_USE_ZLIB AND NOT MSVC)
    execute_process(COMMAND ${CMAKE_COMMAND} --build .
        OUTPUT_QUIET
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${SEAL_THIRDPARTY_DIR}/zlib)
    if(result)
        message(WARNING "Failed to build ZLIB (${result}); disabling `SEAL_USE_ZLIB`")
    endif()
endif()

# Set up the targets
if(SEAL_USE_ZLIB AND NOT MSVC)
    add_subdirectory(
        ${SEAL_THIRDPARTY_DIR}/zlib/src
        EXCLUDE_FROM_ALL)

    # Set the ZLIB include directories; we have to include also ZLIB binary directory because
    # ZLIB creates a file zconf.h into it, which must be visible to the compiler.
    set(SEAL_ZLIB_INCLUDE_DIRS
        ${CMAKE_CURRENT_BINARY_DIR}/thirdparty/zlib/src
        ${SEAL_THIRDPARTY_DIR}/zlib/src)
    set_target_properties(zlibstatic PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${SEAL_ZLIB_INCLUDE_DIRS}")
endif()