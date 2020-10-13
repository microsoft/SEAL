# Download and configure
if(SEAL_USE_MSGSL AND NOT MSVC)
    message(STATUS "Setting up MSGSL ...")
    if(NOT CMAKE_TOOLCHAIN_FILE)
        execute_process(
            COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
            OUTPUT_QUIET
            RESULT_VARIABLE result
            WORKING_DIRECTORY ${SEAL_THIRDPARTY_DIR}/msgsl)
    else()
        seal_create_cache_entries(${SEAL_THIRDPARTY_DIR}/msgsl)
        if(EXISTS ${SEAL_THIRDPARTY_DIR}/msgsl/CMakeCache.txt)
            # Force regenerating make files. When cross compiling we might be
            # compiling more than one platform at a time.
            file(REMOVE ${SEAL_THIRDPARTY_DIR}/msgsl/CMakeCache.txt)
        endif()
        execute_process(
            COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" . -Ccache_init.txt
            OUTPUT_QUIET
            RESULT_VARIABLE result
            WORKING_DIRECTORY ${SEAL_THIRDPARTY_DIR}/msgsl)
    endif()
    if(result)
        message(WARNING "Failed to download MSGSL (${result}); disabling `SEAL_USE_MSGSL`")
    endif()
endif()

# Build
if(SEAL_USE_MSGSL AND NOT MSVC)
    execute_process(
        COMMAND ${CMAKE_COMMAND} --build .
        OUTPUT_QUIET
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${SEAL_THIRDPARTY_DIR}/msgsl)
    if(result)
        message(WARNING "Failed to build MSGSL (${result}); disabling `SEAL_USE_MSGSL`")
    endif()
    set(GSL_CXX_STANDARD "14" CACHE STRING "" FORCE)
    mark_as_advanced(GSL_CXX_STANDARD )
    set(GSL_TEST OFF CACHE BOOL "" FORCE)
    mark_as_advanced(GSL_TEST)
endif()

# Set up the targets
if(SEAL_USE_MSGSL AND NOT MSVC)
    add_subdirectory(
        ${SEAL_THIRDPARTY_DIR}/msgsl/src
        EXCLUDE_FROM_ALL)
    set(SEAL_MSGSL_INCLUDE_DIR ${SEAL_THIRDPARTY_DIR}/msgsl/src/include)
endif()