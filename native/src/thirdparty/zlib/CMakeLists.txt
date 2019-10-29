cmake_minimum_required(VERSION 3.12)

project(ZLIB VERSION 1.2.11 LANGUAGES CXX C)

include(ExternalProject)
ExternalProject_Add(zlib
    GIT_REPOSITORY    https://github.com/madler/zlib.git
    GIT_TAG           v1.2.11
    SOURCE_DIR        "${CMAKE_CURRENT_BINARY_DIR}/zlib-src"
    BINARY_DIR        "${CMAKE_CURRENT_BINARY_DIR}/zlib-src"
    INSTALL_COMMAND   ""
)