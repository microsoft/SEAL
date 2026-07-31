# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Directory holding this file, captured here because macros below expand at their call site.
set(SEAL_CMAKE_MODULE_DIR ${CMAKE_CURRENT_LIST_DIR})

# Set the C++ language version
macro(seal_set_language target)
    if(SEAL_USE_CXX17)
        target_compile_features(${target} PUBLIC cxx_std_17)
    else()
        target_compile_features(${target} PUBLIC cxx_std_14)
    endif()
endmacro()

# Include a file to fetch thirdparty content
macro(seal_fetch_thirdparty_content content_file)
    set(SEAL_FETCHCONTENT_BASE_DIR_OLD ${FETCHCONTENT_BASE_DIR})
    set(FETCHCONTENT_BASE_DIR ${SEAL_THIRDPARTY_DIR} CACHE STRING "" FORCE)
    include(${content_file})
    set(FETCHCONTENT_BASE_DIR ${SEAL_FETCHCONTENT_BASE_DIR_OLD} CACHE STRING "" FORCE)
    unset(SEAL_FETCHCONTENT_BASE_DIR_OLD)
endmacro()

# Set the VERSION property
macro(seal_set_version target)
    set_target_properties(${target} PROPERTIES VERSION ${SEAL_VERSION})
endmacro()

# Set the library filename to reflect version
macro(seal_set_version_filename target)
    set_target_properties(${target} PROPERTIES
        OUTPUT_NAME ${target}-${SEAL_VERSION_MAJOR}.${SEAL_VERSION_MINOR})
endmacro()

# Set the SOVERSION property
macro(seal_set_soversion target)
    set_target_properties(${target} PROPERTIES
        SOVERSION ${SEAL_VERSION_MAJOR}.${SEAL_VERSION_MINOR})
endmacro()

# Set include directories for build and install interfaces
macro(seal_set_include_directories target)
    target_include_directories(${target} PUBLIC
        $<BUILD_INTERFACE:${SEAL_INCLUDES_DIR}>
        $<INSTALL_INTERFACE:${SEAL_INCLUDES_INSTALL_DIR}>)
    target_include_directories(${target} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/native/src/>
        $<INSTALL_INTERFACE:${SEAL_INCLUDES_INSTALL_DIR}>)
endmacro()

# Link a thread library
macro(seal_link_threads target)
    # Require thread library
    if(NOT TARGET Threads::Threads)
        set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
        set(THREADS_PREFER_PTHREAD_FLAG TRUE)
        find_package(Threads REQUIRED)
    endif()

    # Link Threads
    target_link_libraries(${target} PUBLIC Threads::Threads)
endmacro()

# Include target to given export
macro(seal_install_target target export)
    install(TARGETS ${target} EXPORT ${export}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endmacro()

# Manually combine archives, using ${CMAKE_LIBRARY_OUTPUT_DIRECTORY} to keep temporary files.
macro(seal_combine_archives target dependency)
    if(MSVC)
        add_custom_command(TARGET ${target} POST_BUILD
            COMMAND lib.exe /OUT:$<TARGET_FILE:${target}> $<TARGET_FILE:${target}> $<TARGET_FILE:${dependency}>
            DEPENDS $<TARGET_FILE:${target}> $<TARGET_FILE:${dependency}>
            WORKING_DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
    else()
        # CMAKE_AR is the archiver that matches the active toolchain (GNU ar for MinGW,
        # llvm-ar for the Android NDK, emar for Emscripten).
        if(CMAKE_AR)
            set(SEAL_AR_COMMAND "${CMAKE_AR}")
        elseif(EMSCRIPTEN)
            set(SEAL_AR_COMMAND "emar")
        else()
            set(SEAL_AR_COMMAND "ar")
        endif()
        add_custom_command(TARGET ${target} POST_BUILD
            COMMAND ${CMAKE_COMMAND}
                -DSEAL_AR_COMMAND=${SEAL_AR_COMMAND}
                -DSEAL_TARGET_ARCHIVE=$<TARGET_FILE:${target}>
                -DSEAL_DEPENDENCY_ARCHIVE=$<TARGET_FILE:${dependency}>
                -DSEAL_WORK_DIR=${CMAKE_LIBRARY_OUTPUT_DIRECTORY}
                -P ${SEAL_CMAKE_MODULE_DIR}/CombineArchives.cmake
            DEPENDS $<TARGET_FILE:${target}> $<TARGET_FILE:${dependency}>
            WORKING_DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
    endif()
endmacro()

# Add secure compile options
macro(seal_set_secure_compile_options target scope)
    if(MSVC)
        # Build debug symbols for static analysis tools
        target_link_options(${target} ${scope} /DEBUG)

        # Control Flow Guard / Spectre
        target_compile_options(${target} ${scope} /guard:cf)
        target_compile_options(${target} ${scope} /Qspectre)
        target_link_options(${target} ${scope} /guard:cf)
        target_link_options(${target} ${scope} /DYNAMICBASE)
    else()
        # Stack canaries on every function with non-trivial stack usage.
        target_compile_options(${target} ${scope}
            $<$<COMPILE_LANGUAGE:C,CXX>:-fstack-protector-strong>)

        # Standard library hardening: bounds checks on container access,
        # null checks on string_view(const char*), etc. ABI-safe and
        # designed to be cheap enough to leave on in production. Skip in
        # Debug since the stdlibs already enable heavier checks there.
        target_compile_definitions(${target} ${scope}
            $<$<NOT:$<CONFIG:Debug>>:_GLIBCXX_ASSERTIONS>
            $<$<NOT:$<CONFIG:Debug>>:_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST>)

        # ELF-only link-time hardening: full RELRO + immediate binding +
        # non-executable stack. Mach-O equivalents are handled by the Apple
        # linker automatically.
        if(CMAKE_SYSTEM_NAME STREQUAL "Linux" OR CMAKE_SYSTEM_NAME STREQUAL "Android")
            target_link_options(${target} ${scope}
                -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack)
        endif()
    endif()
endmacro()

macro(seal_add_debug_compile_definition target)
    target_compile_definitions(${target}
        PUBLIC $<$<CONFIG:Debug>:SEAL_DEBUG>)
endmacro()
