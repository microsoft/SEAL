# Run benchmarks, so it should have Release mode and enable HEXL
set -xeo pipefail
COMPILER_FLAGS="-DCMAKE_BUILD_TYPE=Release
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

# File location for sealtest and sealbench differs for each platform
sealtest=$(find . -name "sealtest" -o -name "sealtest.exe")
sealbench=$(find . -name "sealbench" -o -name "sealbench.exe")
$sealtest --gtest_output=xml
$sealbench
