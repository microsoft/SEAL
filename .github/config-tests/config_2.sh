# Build shared lib
COMPILER_FLAGS="-DCMAKE_BUILD_TYPE=Release
                -DCMAKE_CXX_COMPILER=clang++
                -DCMAKE_C_COMPILER=clang
                -DSEAL_BUILD_TESTS=ON
                -DSEAL_BUILD_BENCH=ON
                -DSEAL_BUILD_EXAMPLES=ON
                -DSEAL_USE_INTEL_HEXL=ON
                -DSEAL_BUILD_DEPS=ON
                -DSEAL_BUILD_SEAL_C=OFF
                -DBUILD_SHARED_LIBS=ON
                -DSEAL_USE_CXX17=OFF
                -DCMAKE_INSTALL_PREFIX=./"

cmake -B build ${COMPILER_FLAGS}
cmake --build build -j
cmake --build build -j --target install 
build/bin/sealtest --gtest_output=xml
exit $?
