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

# Building and using SEAL for .Net

SEAL provides a .Net Standard library that wraps the functionality in SEAL for use
in .Net development.

## Windows

The Microsoft Visual Studio 2017 solution file SEAL.sln contains the projects necessary
to build the .Net assembly, a backing native dll library, .Net examples and unit tests.

#### Native library

SEAL for .Net requires a native library that is invoked by the managed .Net library.
Build the SEALdll project (net/dll/SEALdll.vcxproj) from SEAL.sln. Building SEALdll results
in the dynamic library SEALdll.dll being created in lib/x64/$(Configuration). This library is
meant to be used only by the .Net library, not by end users. The library needs to be
present in the same directory as your executable when developing a .Net application.

#### .Net library

Build the SEALNet project (net/net/SEALNet.csproj) from SEAL.sln. Building SEALNet results
in the assembly SEALNet.dll being created in net/net/bin/$(Configuration)/netstandard2.0. This
is the assembly you can reference in your application.

#### .Net Examples

Build the SEALNetExamples project (net/examples/SEALNetExamples.csproj) from SEAL.sln.
This results in the assembly SEALNetExamples.dll being created in
net/examples/bin/$(Configuration)/netcoreapp2.1. The project takes care of copying the
native SEALdll library to the output directory.

#### .Net unit tests

Build the SEALNet Test project (net/tests/SEALNetTest.csproj) from SEAL.sln. This results
in the SEALNetTest.dll assembly being created in net/tests/bin/$(Configuration)/netcoreapp2.1.
The project takes care of copying the native SEALdll library to the output directory.

### Using SEAL for .Net in your own application

To use SEAL for .Net in your own application you need to:
1. Add a reference in your project to SEALNet.dll
2. Ensure SEALdll.dll is available for your application when run. The easiest way to ensure
   this is to copy SEALdll.dll to the same directory where your application's executable
   is located.

## Linux and OS X

SEAL for .Net relies on a native shared library that can be easily configured and built
using CMake (>= 3.10) and a modern version of GNU G++ (>= 6.0) or Clang++ (>= 5.0). In OS X
the Xcode toolchain (>= 9.3) will work.

For compiling .Net code you will need to install a .Net Core SDK (>= 2.1). You can follow
these [instructions for installing in Linux](https://dotnet.microsoft.com/download?initial-os=linux),
or for [installing in Mac OS](https://dotnet.microsoft.com/download?initial-os=macos).

### Local use of shared native library

If you only intend to run the examples and unit tests provided with SEAL, you do not need to
install the shared native library, you only need to compile it. The Examples and Unit Tests projects
take care of copying the native shared library to the appropriate assembly output directory.

To compile the shared native library you will need to:
1. Compile SEAL as a static library with Position Independent Code
2. Compile shared native library

The instructions for compiling SEAL are similar to the instructions described previously for a
local install of SEAL.
In the instructions below we additionally speficy that the library is to be compiled as a static
library with position independent code:
````
cd src
cmake -DCMAKE_INSTALL_PREFIX=~/mylibs -DSEAL_LIB_BUILD_TYPE=Static_PIC .
make
make install
cd ..
````
We can now use this library to compile the shared native library required for .Net:
````
cd net/dll
cmake -DCMAKE_PREFIX_PATH=~/mylibs .
make
cd ../..
````

#### .Net library

To build the .Net standard library, do the following:
````
cd net/net
dotnet build
cd ../..
````
You can use the dotnet parameter `--configuration` to build either a Debug or Release version of the assembly.
This will result in a SEALNet.dll assembly being created in net/net/bin/$(Configuration)/netstandard2.0. This
assembly is the one you will want to reference in your own projects.

#### Examples

To build and run the .Net examples do:
````
cd net/examples
dotnet run
cd ../..
````
As mentioned before, the .Net project will copy the shared native library to the assembly output directory.
You can use the dotnet parameter `--configuration-` to run either Debug or Release versions of the examples.

#### Unit tests

To build and run the .Net unit tests do:
````
cd net/tests
dotnet test
cd ../..
````
All unit tests should pass. You can use the dotnet parameter `--configuration` to run Debug or Relase unit tests,
and you can use `--verbosity detailed` to print the list of unit tests that are being run.

### Using SEAL for .Net in your own application

To use SEAL for .Net in your own application you need to:
1. Add a reference in your project to SEALNet.dll
2. Ensure the shared native library is available for your application when run. The easiest way to ensure
   this is to copy SEALdll.dll to the same directory where your application's executable
   is located.

In Linux or Mac OS, if you have root access to the system, you have the option to install the shared native
library globally. Then your application will always be able to find and load it.

To install the shared native library globally, do the following:
````
cd net/dll
cmake .
make
sudo make install
cd ../..
````

# Documentation

The code-base contains extensive and thoroughly commented examples that should 
serve as a self-contained introduction to using SEAL (see examples/examples.cpp). In 
addition, the header files contain detailed comments for the public API.
