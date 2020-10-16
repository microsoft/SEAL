# Google Test
# This follows the example in
# https://github.com/google/googletest/blob/release-1.10.0/googletest/README.md.

# Download and configure
if(SEAL_BUILD_TESTS AND NOT MSVC)
    message(STATUS "Setting up Google Test ...")
    execute_process(
        COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
        OUTPUT_QUIET
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${SEAL_THIRDPARTY_DIR}/googletest)
    if(result)
        message(WARNING "Failed to download Google Test (${result}); disabling `SEAL_BUILD_TESTS`")
    endif()
    set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
    mark_as_advanced(BUILD_GMOCK)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    mark_as_advanced(INSTALL_GTEST)
endif()

# Build
if(SEAL_BUILD_TESTS AND NOT MSVC)
    execute_process(COMMAND ${CMAKE_COMMAND} --build .
        OUTPUT_QUIET
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${SEAL_THIRDPARTY_DIR}/googletest)
    if(result)
        message(WARNING "Failed to build Google Test (${result}); disabling `SEAL_BUILD_TESTS`")
    endif()
endif()

# Set up the targets
if(SEAL_BUILD_TESTS AND NOT MSVC)
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    add_subdirectory(
        ${SEAL_THIRDPARTY_DIR}/googletest/src
        ${SEAL_THIRDPARTY_DIR}/googletest/build
        EXCLUDE_FROM_ALL)
endif()