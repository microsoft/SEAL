BASE_DIR=$(dirname "$0")
SEAL_ROOT_DIR=$BASE_DIR/../../
cd $SEAL_ROOT_DIR
clang-format -i $SEAL_ROOT_DIR/native/**/*.h
clang-format -i $SEAL_ROOT_DIR/native/**/*.cpp