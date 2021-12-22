# Build with pre-built HEXL and shared lib
set -xeuo pipefail
COMPILER_FLAGS="-DCMAKE_BUILD_TYPE=Debug
                -DCMAKE_CXX_COMPILER=clang++
                -DCMAKE_C_COMPILER=clang
                -DSEAL_BUILD_TESTS=OFF
                -DSEAL_BUILD_BENCH=OFF
                -DSEAL_BUILD_EXAMPLES=ON
                -DSEAL_USE_INTEL_HEXL=ON
                -DSEAL_BUILD_DEPS=OFF
                -DSEAL_BUILD_SEAL_C=OFF
                -DSEAL_USE_MSGSL=OFF
                -DSEAL_USE_ZLIB=OFF
                -DSEAL_USE_ZSTD=OFF
                -DBUILD_SHARED_LIBS=ON
                -DSEAL_USE_CXX17=ON
                -DCMAKE_INSTALL_PREFIX=./"

(cd hexl
    cmake -B build -DCMAKE_INSTALL_PREFIX=./
    cmake --build build -j
    cmake --install build
)

export HEXL_DIR=$(pwd)/hexl/lib/cmake/hexl-$HEXL_VER
ls ${HEXL_DIR}
cmake -B build ${COMPILER_FLAGS} -DCMAKE_MODULE_PATH=${HEXL_DIR} -DHEXL_DIR=${HEXL_DIR}
cmake --build build -j
cmake --build build -j --target install
exit $?
