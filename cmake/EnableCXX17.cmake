# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

set(SEAL_USE_STD_BYTE OFF)
set(SEAL_USE_SHARED_MUTEX OFF)
set(SEAL_USE_IF_CONSTEXPR OFF)
set(SEAL_USE_MAYBE_UNUSED OFF)
set(SEAL_USE_NODISCARD OFF)
set(SEAL_USE_STD_FOR_EACH_N OFF)
set(SEAL_LANG_FLAG "-std=c++14")
if(SEAL_USE_CXX17)
    set(SEAL_USE_STD_BYTE ON)
    set(SEAL_USE_SHARED_MUTEX ON)
    set(SEAL_USE_IF_CONSTEXPR ON)
    set(SEAL_USE_MAYBE_UNUSED ON)
    set(SEAL_USE_NODISCARD ON)
    set(SEAL_USE_STD_FOR_EACH_N ON)
    set(SEAL_LANG_FLAG "-std=c++17")
endif()

# In some non-MSVC compilers std::for_each_n is not available even when compiling as C++17
if(SEAL_USE_STD_FOR_EACH_N)
    cmake_push_check_state(RESET)
    set(CMAKE_REQUIRED_QUIET TRUE)

    if(NOT MSVC)
        set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -O0 ${SEAL_LANG_FLAG}")
        check_cxx_source_compiles("
            #include <algorithm>
            int main() {
                int a[1]{ 0 };
                volatile auto fun = std::for_each_n(a, 1, [](auto b) {});
                return 0;
            }"
            USE_STD_FOR_EACH_N
        )
        if(NOT USE_STD_FOR_EACH_N EQUAL 1)
            set(SEAL_USE_STD_FOR_EACH_N OFF)
        endif()
        unset(USE_STD_FOR_EACH_N CACHE)
    endif()

    cmake_pop_check_state()
endif()
