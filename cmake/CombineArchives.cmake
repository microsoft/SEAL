# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Merges a static archive dependency into a target static archive.
#
# This runs in CMake script mode rather than as a shell command line so that object-file
# globbing and cleanup behave identically under cmd.exe and POSIX shells.
#
# Required definitions:
#   SEAL_AR_COMMAND        : archiver to invoke
#   SEAL_TARGET_ARCHIVE    : archive to merge into, updated in place
#   SEAL_DEPENDENCY_ARCHIVE: archive to merge from
#   SEAL_WORK_DIR          : directory to hold extracted objects

foreach(_seal_required SEAL_AR_COMMAND SEAL_TARGET_ARCHIVE SEAL_DEPENDENCY_ARCHIVE SEAL_WORK_DIR)
    if(NOT ${_seal_required})
        message(FATAL_ERROR "CombineArchives.cmake: ${_seal_required} is not set")
    endif()
endforeach()

# Normalize to forward slashes so the CMake file APIs below parse the paths correctly. Only
# backslashes are translated: file(TO_CMAKE_PATH) would additionally split on the host list
# separator, corrupting POSIX paths that contain a colon.
foreach(_seal_path_var SEAL_TARGET_ARCHIVE SEAL_DEPENDENCY_ARCHIVE SEAL_WORK_DIR)
    string(REPLACE "\\" "/" ${_seal_path_var} "${${_seal_path_var}}")
endforeach()

# Extract into a dedicated directory so that unrelated object files in the library output
# directory are never swept into the archive.
get_filename_component(_seal_target_name "${SEAL_TARGET_ARCHIVE}" NAME_WLE)
get_filename_component(_seal_dependency_name "${SEAL_DEPENDENCY_ARCHIVE}" NAME_WLE)
set(_seal_extract_dir "${SEAL_WORK_DIR}/${_seal_target_name}-${_seal_dependency_name}.objs")

file(REMOVE_RECURSE "${_seal_extract_dir}")
file(MAKE_DIRECTORY "${_seal_extract_dir}")

foreach(_seal_archive "${SEAL_TARGET_ARCHIVE}" "${SEAL_DEPENDENCY_ARCHIVE}")
    execute_process(
        COMMAND "${SEAL_AR_COMMAND}" x "${_seal_archive}"
        WORKING_DIRECTORY "${_seal_extract_dir}"
        RESULT_VARIABLE _seal_result
        ERROR_VARIABLE _seal_error)
    if(NOT _seal_result EQUAL 0)
        file(REMOVE_RECURSE "${_seal_extract_dir}")
        message(FATAL_ERROR "Failed to extract ${_seal_archive}: ${_seal_result} ${_seal_error}")
    endif()
endforeach()

file(GLOB _seal_objects LIST_DIRECTORIES false RELATIVE "${_seal_extract_dir}"
    "${_seal_extract_dir}/*.o" "${_seal_extract_dir}/*.obj")
if(NOT _seal_objects)
    file(REMOVE_RECURSE "${_seal_extract_dir}")
    message(FATAL_ERROR "No object files extracted from ${SEAL_TARGET_ARCHIVE} and ${SEAL_DEPENDENCY_ARCHIVE}")
endif()

execute_process(
    COMMAND "${SEAL_AR_COMMAND}" rcs "${SEAL_TARGET_ARCHIVE}" ${_seal_objects}
    WORKING_DIRECTORY "${_seal_extract_dir}"
    RESULT_VARIABLE _seal_result
    ERROR_VARIABLE _seal_error)
if(NOT _seal_result EQUAL 0)
    file(REMOVE_RECURSE "${_seal_extract_dir}")
    message(FATAL_ERROR "Failed to merge ${SEAL_DEPENDENCY_ARCHIVE} into ${SEAL_TARGET_ARCHIVE}: "
        "${_seal_result} ${_seal_error}")
endif()

file(REMOVE_RECURSE "${_seal_extract_dir}")
