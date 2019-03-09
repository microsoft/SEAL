# Microsoft SEAL

Microsoft SEAL is an easy-to-use homomorphic encryption library developed by researchers in 
the Cryptography Research group at Microsoft Research. Microsoft SEAL is written in modern 
standard C++ and has no external dependencies, making it easy to compile and run in many 
different environments.

For more information about the Microsoft SEAL project, see [http://sealcrypto.org](https://www.microsoft.com/en-us/research/project/microsoft-seal).

# License

Microsoft SEAL is licensed under the MIT license; see [LICENSE](LICENSE).

# Contents
- [Building and Using Microsoft SEAL](#building-and-using-microsoft-seal)
  - [Windows](#windows)
  - [Linux and macOS](#linux-and-macos)
- [Building and Using Microsoft SEAL for .NET](#building-and-using-microsoft-seal-for-.net)
  - [Windows](#windows-1)
  - [Linux and macOS](#linux-and-macos-1)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [Citing Microsoft SEAL](#citing-microsoft-seal)

# Building and Using Microsoft SEAL 

## Windows

Microsoft SEAL comes with a Microsoft Visual Studio 2017 solution file `SEAL.sln` that can be
used to conveniently build the library, examples, and unit tests.

#### Debug and Release builds

You can easily switch from Visual Studio build configuration menu whether Microsoft SEAL should be
built in `Debug` mode (no optimizations) or in `Release` mode. Please note that `Debug`
mode should not be used except for debugging SEAL itself, as the performance will be 
orders of magnitude worse than in `Release` mode.

#### Library

Build the SEAL project `native\src\SEAL.vcxproj` from `SEAL.sln`. This results
in the static library `seal.lib` to be created in `native\lib\$(Platform)\$(Configuration)`. When
linking with applications, you need to add `native\src\` (full path) as an include directory
for SEAL header files.

#### Examples

Build the SEALExamples project `native\examples\SEALExamples.vcxproj` from `SEAL.sln`.
This results in an executable `sealexamples.exe` to be created in `native\bin\$(Platform)\$(Configuration)`.

#### Unit tests

The unit tests require the Google Test framework to be installed. The appropriate 
NuGet package is already listed in `native\tests\packages.config`, so once you attempt to build 
the SEALTest project `native\tests\SEALTest.vcxproj` from `SEAL.sln` Visual Studio will 
automatically download and install it for you.

## Linux and macOS

Microsoft SEAL is very easy to configure and build in Linux and macOS using CMake (>= 3.10). 
A modern version of GNU G++ (>= 6.0) or Clang++ (>= 5.0) is needed. In macOS the 
Xcode toolchain (>= 9.3) will work.

In macOS you will need CMake with command line tools. For this, you can either 
1. install the cmake package with [Homebrew](https://brew.sh), or
2. download CMake directly from [https://cmake.org/download](https://cmake.org/download) and [enable command line tools](https://stackoverflow.com/questions/30668601/installing-cmake-command-line-tools-on-a-mac).

Below we give instructions for how to configure, build, and install SEAL either 
system-wide (global install), or for a single user (local install). A system-wide
install requires elevated (root) privileges.

#### Debug and Release builds

You can easily switch from CMake configuration options whether Microsoft SEAL should be built in 
`Debug` mode (no optimizations) or in `Release` mode. Please note that `Debug` mode should not 
be used except for debugging Microsoft SEAL itself, as the performance will be orders of magnitude 
worse than in `Release` mode.

### Global install

#### Library

If you have root access to the system you can install Microsoft SEAL system-wide as follows:
````
cd native/src
cmake .
make
sudo make install
cd ../..
````
#### Examples

To build the examples do:
````
cd native/examples
cmake .
make
cd ../..
````

After completing the above steps the `sealexamples` executable can be found in `native/bin/`. 
See `native/examples/CMakeLists.txt` for how to link Microsoft SEAL with your own project using CMake.

#### Unit tests

To build the unit tests, make sure you have the Google Test library `libgtest-dev`
installed. Then do: 
````
cd native/tests
cmake .
make
cd ../..
````

After completing these steps the `sealtest` executable can be found in `native/bin/`. All unit 
tests should pass successfully.

### Local install

#### Library

To install Microsoft SEAL locally, e.g., to `~/mylibs/`, do the following:
````
cd native/src
cmake -DCMAKE_INSTALL_PREFIX=~/mylibs .
make
make install
cd ../..
````

#### Examples 

To build the examples do:
````
cd native/examples
cmake -DCMAKE_PREFIX_PATH=~/mylibs .
make
cd ../..
````

After completing the above steps the `sealexamples` executable can be found in `native/bin/`. 
See `native/examples/CMakeLists.txt` for how to link Microsoft SEAL with your own project using CMake.

#### Unit tests

To build the unit tests, make sure you have the Google Test library `libgtest-dev`
installed. Then do:
````
cd native/tests
cmake -DCMAKE_PREFIX_PATH=~/mylibs .
make
cd ../..
````

After completing these steps the `sealtest` executable can be found in `native/bin/`. All unit 
tests should pass successfully.

# Building and Using Microsoft SEAL for .NET

Microsoft SEAL provides a .NET Standard library that wraps the functionality in Microsoft SEAL
for use in .NET development.

## Windows

The Microsoft Visual Studio 2017 solution file `SEAL.sln` contains the projects necessary
to build the .NET assembly, a backing native shared library, .NET examples, and unit tests.

#### Native library

Microsoft SEAL for .NET requires a native library that is invoked by the managed .NET library.
Build the SEALNetNative project `dotnet\native\SEALNetNative.vcxproj` from `SEAL.sln`. 
Building SEALNetNative results in the dynamic library `sealnetnative.dll` to be created 
in `dotnet\lib\$(Platform)\$(Configuration)`. This library is meant to be used only by the 
.NET library, not by end users, and needs to be present in the same directory as your 
executable when developing a .NET application.

#### .NET library

Once you have built the shared native library (see above), build the SEALNet project 
`dotnet\src\SEALNet.csproj` from `SEAL.sln`. Building SEALNet results in the assembly 
`SEALNet.dll` to be created in `dotnet\lib\$(Configuration)\netstandard2.0`. This
is the assembly you can reference in your application.

#### .NET examples

Build the SEALNetExamples project `dotnet\examples\SEALNetExamples.csproj` from `SEAL.sln`.
This results in the assembly `SEALNetExamples.dll` to be created in
`dotnet\bin\$(Configuration)\netcoreapp2.1`. The project takes care of copying the
native SEALNetNative library to the output directory.

#### .NET unit tests

Build the SEALNet Test project `dotnet\tests\SEALNetTest.csproj` from `SEAL.sln`. This results
in the `SEALNetTest.dll` assembly to be created in `dotnet\lib\$(Configuration)\netcoreapp2.1`.
The project takes care of copying the native SEALNetNative library to the output directory.

### Using Microsoft SEAL for .NET in your own application

To use Microsoft SEAL for .NET in your own application you need to:
1. add a reference in your project to `SEALNet.dll`;
2. ensure `sealnetnative.dll` is available for your application when run. The easiest way to ensure
   this is to copy `sealnetnative.dll` to the same directory where your application's executable
   is located.

Alternatively, you can build and use a NuGet package; see instructions in [NUGET.md](dotnet/nuget/NUGET.md).

## Linux and macOS

Microsoft SEAL for .NET relies on a native shared library that can be easily configured and built
using CMake (>= 3.10) and a modern version of GNU G++ (>= 6.0) or Clang++ (>= 5.0). In macOS
the Xcode toolchain (>= 9.3) will work.

For compiling .NET code you will need to install a .NET Core SDK (>= 2.1). You can follow
these [instructions for installing in Linux](https://dotnet.microsoft.com/download?initial-os=linux),
or for [installing in macOS](https://dotnet.microsoft.com/download?initial-os=macos).

### Local use of shared native library

If you only intend to run the examples and unit tests provided with Microsoft SEAL, 
you do not need to install the native shared library, you only need to compile it. 
The SEALNetExamples and SEALNetTest projects take care of copying the native shared 
library to the appropriate assembly output directory.

To compile the native shared library you will need to:
1. Compile Microsoft SEAL as a static or shared library with Position-Independent Code (PIC);
2. Compile native shared library.

The instructions for compiling Microsoft SEAL are similar to the instructions described 
[above](#linux-and-macos) for a global or local install. Make sure the CMake configuration 
option `SEAL_LIB_BUILD_TYPE` is set to either `Static_PIC` (default) or `Shared`. Assuming 
Microsoft SEAL was built and installed globally using the default CMake configuration 
options, we can immediately use it to compile the shared native library required for .NET:
````
cd dotnet/native
cmake .
make
cd ../..
````
If Microsoft SEAL was installed locally instead, use:
````
cd dotnet/native
cmake -DCMAKE_PREFIX_PATH=~/mylibs .
make
cd ../..
````

#### .NET library

To build the .NET Standard library, do the following:
````
cd dotnet/src
dotnet build
cd ../..
````
You can use the `dotnet` parameter `--configuration <Debug|Release>` to build either a `Debug` or `Release` version of the assembly.
This will result in a `SEALNet.dll` assembly to be created in `dotnet/lib/$(Configuration)/netstandard2.0`. This
assembly is the one you will want to reference in your own projects.

#### Examples

To build and run the .NET examples, do:
````
cd dotnet/examples
dotnet run
cd ../..
````
As mentioned before, the .NET project will copy the shared native library to the assembly 
output directory. You can use the `dotnet` parameter `--configuration <Debug|Release>` to 
run either `Debug` or `Release` versions of the examples.

#### Unit tests

To build and run the .NET unit tests, do:
````
cd dotnet/tests
dotnet test
cd ../..
````
All unit tests should pass. You can use the `dotnet` parameter `--configuration <Debug|Release>` to run `Debug` or `Relase` unit tests,
and you can use `--verbosity detailed` to print the list of unit tests that are being run.

### Using Microsoft SEAL for .NET in your own application

To use Microsoft SEAL for .NET in your own application you need to:
1. add a reference in your project to `SEALNet.dll`;
2. ensure the native shared library is available for your application when run. The easiest way to ensure this is to copy `libsealnetnative.so` to the same directory where your application's executable is located.

In Linux or macOS, if you have root access to the system, you have the option to install the 
native shared library globally. Then your application will always be able to find and load it.

Assuming Microsoft SEAL is build and installed globally, you can install the shared native 
library globally as follows:
````
cd dotnet/native
cmake  .
make
sudo make install
cd ../..
````

# Documentation

The code-base contains extensive and thoroughly commented examples that should 
serve as a self-contained introduction to using Microsoft SEAL (see `native/examples/examples.cpp` or `dotnet/examples/Examples.cs`). 
In addition, the header files contain detailed comments for the public API.

For requests, bug reports and technical questions, please see [Issues.md](Issues.md).

# Contributing

This project welcomes contributions and suggestions. Most contributions require you 
to agree to a Contributor License Agreement (CLA) declaring that you have the right to,
and actually do, grant us the rights to use your contribution. For details, visit 
https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need 
to provide a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow 
the instructions provided by the bot. You will only need to do this once across all 
repos using our CLA.

Pull requests must be submitted to the branch called `contrib`.

This project has adopted the 
[Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the 
[Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) 
or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional 
questions or comments.

# Citing Microsoft SEAL

To cite Microsoft SEAL in academic papers, please use the following BibTeX entries.

### Version 3.2

	@misc{sealcrypto,
        title = {{M}icrosoft {SEAL} (release 3.2)},
	    howpublished = {\url{https://github.com/Microsoft/SEAL}},
	    month = feb,
	    year = 2019,
	    note = {Microsoft Research, Redmond, WA.},
	    key = {SEAL}
	}

### Version 3.1

	@misc{sealcrypto,
        title = {{M}icrosoft {SEAL} (release 3.1)},
	    howpublished = {\url{https://github.com/Microsoft/SEAL}},
	    month = dec,
	    year = 2018,
	    note = {Microsoft Research, Redmond, WA.},
	    key = {SEAL}
	}

### Version 3.0
    @misc{sealcrypto,
	    title = {{M}icrosoft {SEAL} (release 3.0)},
	    howpublished = {\url{http://sealcrypto.org}},
	    month = oct,
	    year = 2018,
	    note = {Microsoft Research, Redmond, WA.},
	    key = {SEAL}
    }