# Introduction

Microsoft Simple Encrypted Arithmetic Library (Microsoft SEAL) is an easy-to-use 
homomorphic encryption library developed by researchers in the Cryptography 
Research group at Microsoft Research. SEAL is written in modern standard C++ and 
has no external dependencies, making it easy to compile and run in many different 
environments.

For more information about the Microsoft SEAL project, see [http://sealcrypto.org](http://sealcrypto.org).

# License

SEAL is licensed under the MIT license; see LICENSE.

# Building and using SEAL 

## Windows

SEAL comes with a Microsoft Visual Studio 2017 solution file SEAL.sln that can be
used to conveniently build the library, examples, and unit tests.

#### Debug and release builds

You can easily switch from Visual Studio configuration menu whether SEAL should be
built in Debug mode (no optimizations) or in Release mode. Please note that Debug
mode should not be used except for debugging SEAL itself, as the performance will be 
orders of magnitude worse than in Release mode.

#### Library

Build the SEAL project (src/SEAL.vcxproj) from SEAL.sln. Building SEAL results
in the static library seal.lib to be created in lib/x64/$(Configuration). When
linking with applications, you need to add src/ (full path) as an include directory
for SEAL header files.

#### Examples

Build the SEALExamples project (examples/SEALExamples.vcxproj) from SEAL.sln.
This results in an executable sealexamples.exe to be created in bin/x64/$(Configuration).

#### Unit tests

The unit tests require the Google Test framework to be installed. The appropriate 
NuGet package is already listed in tests/packages.config, so once you attempt to build 
the SEALTest project (tests/SEALTest.vcxproj) from SEAL.sln Visual Studio will 
automatically download and install it for you.

## Linux and OS X

SEAL is very easy to configure and build in Linux and OS X using CMake (>= 3.10). 
A modern version of GNU G++ (>= 6.0) or Clang++ (>= 5.0) is needed. In OS X the 
Xcode toolchain (>= 9.3) will work.

In OS X you will need CMake with command line tools. For this, you can either 
1. install the cmake package with [Homebrew](https://brew.sh), or
2. download CMake directly from [https://cmake.org/download](https://cmake.org/download) and [enable command line tools](https://stackoverflow.com/questions/30668601/installing-cmake-command-line-tools-on-a-mac).

Below we give instructions for how to configure, build, and install SEAL either 
system-wide (global install), or for a single user (local install). A system-wide
install requires elevated (root) privileges.

#### Debug and release builds

You can easily switch from CMake configuration options whether SEAL should be built in 
Debug mode (no optimizations) or in Release mode. Please note that Debug mode should not 
be used except for debugging SEAL itself, as the performance will be orders of magnitude 
worse than in Release mode.

### Global install

#### Library

If you have root access to the system you can install SEAL system-wide as follows:
````
cd src
cmake .
make
sudo make install
cd ..
````
#### Examples

To build the examples do:
````
cd examples
cmake .
make
cd ..
````

After completing the above steps the sealexamples executable can be found in bin/. 
See examples/CMakeLists.txt for how to link SEAL with your own project using cmake.

#### Unit tests

To build the unit tests, make sure you have the Google Test library (libgtest-dev)
installed. Then do: 
````
cd tests
cmake .
make
cd ..
````

After completing these steps the sealtest executable can be found in bin/. All unit 
tests should pass successfully.

### Local install

#### Library

To install SEAL locally, e.g., to ~/mylibs, do the following:
````
cd src
cmake -DCMAKE_INSTALL_PREFIX=~/mylibs .
make
make install
cd ..
````

#### Examples 

To build the examples do:
````
cd examples
cmake -DCMAKE_PREFIX_PATH=~/mylibs .
make
cd ..
````

After completing the above steps the sealexamples executable can be found in bin/. 
See examples/CMakeLists.txt for how to link SEAL with your own project using cmake.

#### Unit tests

To build the unit tests, make sure you have the Google Test library (libgtest-dev)
installed. Then do:
````
cd tests
cmake -DCMAKE_PREFIX_PATH=~/mylibs .
make
cd ..
````

After completing these steps the sealtest executable can be found in bin/. All unit 
tests should pass successfully.

# Documentation

The code-base contains extensive and thoroughly commented examples that should 
serve as a self-contained introduction to using SEAL (see examples/examples.cpp). In 
addition, the header files contain detailed comments for the public API.
