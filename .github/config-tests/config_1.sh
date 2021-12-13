# Config 1 is the only one to run benchmarks, so it should have Release mode and enable HEXL
set -x
COMPILER_FLAGS="-DCMAKE_BUILD_TYPE=Release
                -DCMAKE_CXX_COMPILER=clang++
                -DCMAKE_C_COMPILER=clang
                -DSEAL_BUILD_TESTS=ON
                -DSEAL_BUILD_BENCH=ON
                -DSEAL_BUILD_EXAMPLES=ON
                -DSEAL_USE_INTEL_HEXL=ON
                -DSEAL_BUILD_DEPS=ON
                -DSEAL_BUILD_SEAL_C=ON
                -DBUILD_SHARED_LIBS=OFF
                -DSEAL_USE_CXX17=ON
                -DCMAKE_INSTALL_PREFIX=./"

cmake -B build ${COMPILER_FLAGS}
cmake --build build -j --config Release
cmake --build build -j --target install --config Release

echo "HELLO"
ls -la build
ls -la build/bin
echo "HELLO END"

build/bin/sealtest --gtest_output=xml
build/bin/sealbench
exit $?
