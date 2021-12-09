# Build in debug mode, with prebuilt SEAL, and with no HEXL. Finally, run seal examples.
set -x
COMPILER_FLAGS="-DCMAKE_BUILD_TYPE=Debug
                -DMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG=build/bin/Debug
                -DCMAKE_CXX_COMPILER=g++
                -DCMAKE_C_COMPILER=gcc
                -DSEAL_BUILD_TESTS=ON
                -DSEAL_BUILD_BENCH=ON
                -DSEAL_BUILD_EXAMPLES=OFF
                -DSEAL_USE_INTEL_HEXL=OFF
                -DSEAL_BUILD_DEPS=ON
                -DSEAL_BUILD_SEAL_C=ON
                -DSEAL_USE_CXX17=ON
                -DCMAKE_INSTALL_PREFIX=./"

cmake -B build ${COMPILER_FLAGS}
cmake --build build -j --config Debug
cmake --build build -j --target install --config Debug
build/bin/Debug/sealtest --gtest_output=xml

ls -la build/bin
ls -la build/bin/Debug
find . -name "sealtest"
# Build examples using pre-built SEAL
export SEAL_DIR=$(pwd)/lib/cmake/SEAL-$SEAL_VER/
ls ${SEAL_DIR}
cd native/examples/
cmake -B build -DSEAL_DIR=${SEAL_DIR} -DCMAKE_MODULE_PATH=${SEAL_DIR}
cmake --build build -j

# Run examples 1, 2, 3, 4, 5, and 6 before exiting (0)
echo 1 2 3 4 5 6 0 | build/bin/Debug/sealexamples
exit $?
